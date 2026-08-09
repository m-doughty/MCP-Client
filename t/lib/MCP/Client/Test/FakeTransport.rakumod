=begin pod

=head1 NAME

MCP::Client::Test::FakeTransport - a scripted MCP::Client::Transport for tests

=head1 DESCRIPTION

A transport that answers from a script instead of from a server, and records
everything the client sent. It exists so the era machine, the multi round-trip
loop and the typed API can be tested exhaustively — including the failure paths
a real server will not produce on demand — with no subprocess, no socket and no
timing.

Responses are queued per method, so a test scripts C<server/discover> and
C<tools/call> independently and does not care what order the client asks in. A
method with no script left is a test bug, not a server behaviour, and is
reported as one.

=head2 Scripting

Each scripted answer is a hash with exactly one of:

=item C<< result => %h >> — kept, after C<normalize-result>, as a server result.
=item C<< raw => $anything >> — kept verbatim, C<normalize-result> included, so
      a test can hand the client a JSON C<null> or a string where a result
      belongs.
=item C<< error => { code, message?, data? } >> — broken with an
      C<X::MCP::Client::Protocol>, exactly as a real transport does for a
      JSON-RPC error response.
=item C<< timeout => $seconds >> — broken with an C<X::MCP::Client::Timeout>.
=item C<< throw => $exception >> — broken with that exception, for
      C<ServerGone> and friends.
=item C<< respond => -> %msg { ... } >> — called with the outbound message and
      returns any of the above, for answers that depend on what was asked.

Any of them may also carry C<< notify => [%n1, %n2] >>: those notifications are
delivered to the request's C<&on-notification> before it is settled.

=head1 EXAMPLES

The era probe, twice over:

=begin code :lang<raku>
use MCP::Client;
use MCP::Client::Test::FakeTransport;

my $wire = MCP::Client::Test::FakeTransport.new;
$wire.script('server/discover', {
	result => {
		supportedVersions => ['2026-07-28'],
		capabilities      => { tools => {} },
		_meta => { 'io.modelcontextprotocol/serverInfo' => { name => 'fake' } },
	},
});

my $client = MCP::Client.new(transport => $wire);
is $client.era, 'modern';
is $wire.sent-methods, ['server/discover'];
=end code

=begin code :lang<raku>
my $wire = MCP::Client::Test::FakeTransport.new;
$wire.script('server/discover', { error => { code => -32601, message => 'nope' } });
$wire.script('initialize', {
	result => { protocolVersion => '2025-11-25', capabilities => {}, serverInfo => {} },
});

my $client = MCP::Client.new(transport => $wire);
is $client.era, 'legacy';
is $wire.notified-methods, ['notifications/initialized'];
=end code

Multi round-trips, one entry per round:

=begin code :lang<raku>
$wire.script('tools/call',
	{ result => {
		resultType   => 'input_required',
		inputRequests => { ask => { method => 'elicitation/create', params => {} } },
		requestState  => 'opaque-blob',
	} },
	# NB: the trailing comma -- a bare [%h] flattens the hash into Pairs.
	{ result => { content => [{ type => 'text', text => 'done' },] } },
);

my %answer = $client.call-tool('t', {});
is $wire.requests-for('tools/call')[1]<params><requestState>, 'opaque-blob';
=end code

=end pod

use MCP::Server::Protocol;
use MCP::Client::Exceptions;
use MCP::Client::Protocol;
use MCP::Client::Transport;

unit class MCP::Client::Test::FakeTransport does MCP::Client::Transport;

#| Every outbound message in order, requests and notifications alike.
has @.sent;

#| Just the requests, in order.
has @.requests;

#| Just the notifications, in order.
has @.notified;

#| Every C<&on-notification> callback a request arrived with, so a test can
#| push a notification at the client after the fact.
has @.listeners;

#| The cancellation promises requests arrived with, and the timeouts they asked
#| for, positionally matched to C<@.requests>.
has @.cancellations;
has @.timeouts;

#| How many times C<close> was called.
has Int $.closes = 0;

has %!scripts;
has @!fallback;
has Lock $!lock .= new;
has Bool $!open = True;

#| Queue one or more answers for a method. Answers are consumed in order.
method script(Str:D $method, **@answers --> ::?CLASS:D) {
	self!check(@answers);
	$!lock.protect: {
		%!scripts{$method} //= [];
		%!scripts{$method}.append(@answers);
	}
	self;
}

#| Queue answers used for any method with no script of its own, in order.
method script-any(**@answers --> ::?CLASS:D) {
	self!check(@answers);
	$!lock.protect: { @!fallback.append(@answers) };
	self;
}

# The slurpies above are ** rather than * on purpose: a single Hash handed to a
# flattening slurpy arrives as a list of Pairs, which would silently turn one
# two-key answer into two one-key answers -- and since hash order is random,
# into a test that passes on some runs. This checks the invariant anyway, and
# catches a key typo while it is still a one-line fix.
method !check(@answers --> Nil) {
	my $allowed = <result raw error timeout throw respond notify>.Set;
	for @answers -> $answer {
		die "FakeTransport: a scripted answer must be a Hash, not a {$answer.^name}"
			unless $answer ~~ Associative && $answer !~~ Pair;
		my @unknown = $answer.keys.grep({ !$allowed{$_} }).sort;
		die "FakeTransport: unknown key(s) in a scripted answer: {@unknown.join(', ')}"
			~ " (expected any of {$allowed.keys.sort.join(', ')})"
			if @unknown;
	}
}

#| The methods of every request sent, in order.
method sent-methods(--> List:D) {
	$!lock.protect: { @!requests.map({ $_<method> }).List };
}

#| The methods of every notification sent, in order.
method notified-methods(--> List:D) {
	$!lock.protect: { @!notified.map({ $_<method> }).List };
}

#| Every request for one method, in order.
method requests-for(Str:D $method --> List:D) {
	$!lock.protect: { @!requests.grep({ $_<method> eq $method }).List };
}

#| The JSON-RPC ids of every request sent, in order.
method sent-ids(--> List:D) {
	$!lock.protect: { @!requests.map({ $_<id> }).List };
}

#| Answers still queued but never used — a scripted expectation the client did
#| not meet.
method unused(--> Int:D) {
	$!lock.protect: { %!scripts.values.map(*.elems).sum + @!fallback.elems };
}

#| Push a notification at every request that is still listening. Used for the
#| notifications a real server sends unprompted.
method emit-notification(%note --> Nil) {
	my @taps = $!lock.protect: { @!listeners.List };
	for @taps -> &tap {
		&tap(%note);
	}
}

method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
	my $answer;

	$!lock.protect: {
		@!sent.push(%msg);
		@!requests.push(%msg);
		@!cancellations.push($cancelled);
		@!timeouts.push($timeout);
		@!listeners.push(&on-notification) if &on-notification;

		unless $!open {
			$answer = X::MCP::Client::TransportClosed.new(
				detail => 'FakeTransport was closed',
			);
		}
	}

	return Promise.broken($answer) if $answer ~~ Exception;

	my $script = self!next-answer(%msg<method> // '');
	return Promise.broken($script) if $script ~~ Exception;

	my %answer = $script ~~ Associative ?? $script.Hash !! {};

	# A responder is resolved before anything else in the entry is read, so it
	# may decide notifications and outcome together.
	if %answer<respond> ~~ Callable {
		my $dynamic = %answer<respond>(%msg);
		%answer = $dynamic ~~ Associative ?? $dynamic.Hash !! {};
	}

	if %answer<notify> ~~ Positional && &on-notification {
		on-notification($_) for %answer<notify>.list;
	}

	if %answer<error>:exists {
		my %error = %answer<error> ~~ Associative ?? %answer<error>.Hash !! {};
		return Promise.broken(X::MCP::Client::Protocol.new(
			detail => %error<message> // 'server error',
			code   => (%error<code> ~~ Int ?? %error<code> !! Int),
			data   => %error<data>,
		));
	}

	if %answer<timeout>:exists {
		return Promise.broken(X::MCP::Client::Timeout.new(
			seconds => (%answer<timeout> ~~ Real ?? %answer<timeout> !! 5),
			method  => (%msg<method> // Str),
			id      => %msg<id>,
		));
	}

	if %answer<throw>:exists {
		my $thrown = %answer<throw>;
		return Promise.broken($thrown ~~ Exception
			?? $thrown
			!! X::MCP::Client.new(detail => 'FakeTransport was told to throw ' ~ $thrown.raku));
	}

	# `raw` goes through normalize-result exactly as a real transport's does:
	# the point of the entry is to prove the client survives a result that is
	# not a well-formed object, not to bypass the transport contract.
	return Promise.kept(normalize-result(%answer<raw>)) if %answer<raw>:exists;

	Promise.kept(normalize-result(%answer<result> // {}));
}

method notify(%msg --> Nil) {
	$!lock.protect: {
		@!sent.push(%msg);
		@!notified.push(%msg);
	}
}

method close(--> Nil) {
	$!lock.protect: {
		$!open = False;
		++$!closes;
	}
}

method alive(--> Bool) {
	$!lock.protect: { $!open }
}

# The next scripted answer for a method, or the exception a test should see
# when there is none: a client asking something the test never anticipated is
# a finding, and silently answering {} would hide it.
method !next-answer(Str:D $method) {
	$!lock.protect: {
		my $answer;
		if (%!scripts{$method}:exists) && %!scripts{$method}.elems {
			$answer = %!scripts{$method}.shift;
		}
		elsif @!fallback.elems {
			$answer = @!fallback.shift;
		}
		else {
			$answer = X::MCP::Client::Protocol.new(
				detail => "FakeTransport has no scripted answer left for '$method'",
			);
		}
		$answer;
	}
}
