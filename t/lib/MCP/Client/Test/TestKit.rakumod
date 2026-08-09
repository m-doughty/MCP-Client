=begin pod

=head1 NAME

MCP::Client::Test::TestKit - a toolkit with one of everything, for client tests

=head1 DESCRIPTION

An C<MCP::Server::Toolkit> that exists to be talked to. It registers a tool for
each shape a client has to survive — an answer, a slow answer, an exception, a
log notification — plus a prompt and two resources, so every catalog a client
knows how to list has something in it and the cacheable and uncacheable halves
of C<resources/read> are both covered.

Everything it registers is thread-safe: the tests drive it through transports
that dispatch on their own threads, and several calls may be in flight at once.

=head2 What is in it

=item C<echo> — returns its C<text> argument. The happy path.
=item C<slow> — sleeps for C<ms> milliseconds (default C<:$slow-ms>) and then
      answers. For "is this request still in flight?" and for timeouts.
=item C<dying> — throws. C<MCP::Server> turns that into a tool result with
      C<isError>, which is the shape a client must not mistake for a protocol
      failure.
=item C<noisy> — emits a C<notifications/message> at the level asked for
      (default C<info>) and then answers. It goes through the request context,
      so it respects the 2026-07-28 rule that a server MUST NOT log for a
      request that did not opt in through C<_meta> C<logLevel>.
=item prompt C<greeting> — one argument, one message.
=item resource C<test://cached> — carries C<ttlMs> and C<cacheScope>, so a
      client that caches correctly reads it from the server exactly once.
=item resource C<test://volatile> — carries neither, so a client that caches
      correctly reads it from the server every single time.

Both resources count their reads (C<count-of('read:cached')>), which is how a
test proves a cache hit never reached the handler, not merely that it never
reached the transport.

=head1 EXAMPLES

=begin code :lang<raku>
use MCP::Server;
use MCP::Client::Test::TestKit;

my $kit = MCP::Client::Test::TestKit.new(slow-ms => 50);
my $server = MCP::Server.new(:name<fixture>, :version<1.0.0>);
$server.plug($kit);

# ... drive the server ...
say $kit.count-of('echo');          # how many times the echo tool ran
=end code

Plugged under a prefix, everything it registers is namespaced, which is how the
registry tests build a server with two of it:

=begin code :lang<raku>
$server.plug(MCP::Client::Test::TestKit.new, prefix => 'other');   # other_echo, ...
=end code

=end pod

use MCP::Server::Protocol;
use MCP::Server::Toolkit;

unit class MCP::Client::Test::TestKit does MCP::Server::Toolkit;

#| How long the C<slow> tool sleeps when the call names no C<ms> of its own.
has Real:D $.slow-ms = 200;

#| Body of the cacheable resource.
has Str:D $.cached-body = 'cached body';

#| C<ttlMs> reported for the cacheable resource. An hour: long enough that no
#| test can expire it by accident.
has Int:D $.cached-ttl-ms = 3_600_000;

has Lock $!lock .= new;
has %!counts;

#| How many times a named handler has run.
method count-of(Str:D $name --> Int:D) {
	$!lock.protect: { %!counts{$name} // 0 }
}

#| Every counter, for a test that wants to assert on the lot.
method counts(--> Hash:D) {
	$!lock.protect: { %!counts.Hash }
}

method !bump(Str:D $name --> Nil) {
	$!lock.protect: { %!counts{$name} = (%!counts{$name} // 0) + 1 };
}

method register($registrar) {
	$registrar.tool: 'echo',
		description => 'Return the text it was given',
		params => {
			text => { type => 'string', description => 'What to echo back', required => True },
		},
		handler => -> :%args {
			self!bump('echo');
			(%args<text> // '').Str;
		};

	$registrar.tool: 'slow',
		description => 'Answer after a delay',
		params => {
			ms => { type => 'integer', description => 'Milliseconds to take over it' },
		},
		handler => -> :%args {
			self!bump('slow');
			my $ms = %args<ms> ~~ Real:D ?? %args<ms>.Real !! $!slow-ms;
			sleep $ms / 1000 if $ms > 0;
			"slept {$ms}ms";
		};

	$registrar.tool: 'dying',
		description => 'Throw, so the isError path can be tested',
		params => {
			reason => { type => 'string', description => 'What to blame' },
		},
		handler => -> :%args {
			self!bump('dying');
			die (%args<reason> // 'the tool exploded').Str;
		};

	$registrar.tool: 'noisy',
		description => 'Emit a log notification, then answer',
		params => {
			level => { type => 'string', description => 'RFC 5424 level to log at' },
			text  => { type => 'string', description => 'What to log' },
		},
		handler => -> :%args {
			self!bump('noisy');
			my $level = (%args<level> ~~ Str:D && (%LOG-LEVELS{%args<level>}:exists))
				?? %args<level> !! 'info';
			my $text = (%args<text> // 'a log line from the test kit').Str;

			# Straight through the request context rather than through
			# MCP::Server.log: the toolkit has no reference to the server, and
			# the context is the thing that knows whether this request opted in
			# to logging at all. Nothing is written to $*ERR, which matters when
			# the server is running inside a test harness reading TAP off stdout.
			with $*MCP-REQUEST-CONTEXT {
				.emit-notification(notification('notifications/message', {
					level => $level, logger => 'test-kit', data => $text,
				})) if .wants-log($level);
			}

			"logged at $level";
		};

	$registrar.prompt: 'greeting',
		description => 'Say hello to somebody',
		arguments => [
			{ name => 'name', description => 'Who to greet', required => True },
		],
		handler => -> :%args {
			self!bump('greeting');
			"Hello, {(%args<name> // 'world').Str}!";
		};

	$registrar.resource: 'test://cached',
		name => 'Cacheable body',
		description => 'A resource the server promises will not change for an hour',
		mime-type => 'text/plain',
		ttl-ms => $!cached-ttl-ms,
		cache-scope => 'public',
		handler => -> :%args {
			self!bump('read:cached');
			$!cached-body;
		};

	$registrar.resource: 'test://volatile',
		name => 'Uncacheable body',
		description => 'A resource the server will not vouch for',
		mime-type => 'text/plain',
		handler => -> :%args {
			self!bump('read:volatile');
			'volatile body ' ~ self.count-of('read:volatile');
		};
}
