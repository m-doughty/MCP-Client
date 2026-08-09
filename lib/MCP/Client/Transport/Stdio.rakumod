=begin pod

=head1 NAME

MCP::Client::Transport::Stdio - JSON-RPC over a child process's stdin and stdout

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client;
use MCP::Client::Transport::Stdio;

my $wire = MCP::Client::Transport::Stdio.new(
	command   => 'my-mcp-server',
	args      => ['--stdio'],
	env       => { MY_API_KEY => %*ENV<MY_API_KEY> // '' },
	on-stderr => -> Str:D $line { note "[server] $line" },
	on-log    => -> Str:D $message { note "[stdio] $message" },
);

my $mcp = MCP::Client.new(transport => $wire);
say $mcp.call-tool('echo', { text => 'hi' })<content>[0]<text>;
$mcp.close;
=end code

=head1 DESCRIPTION

The transport almost every MCP server in the wild speaks: the server is a child
process, one JSON-RPC message per line goes down its stdin, one JSON-RPC message
per line comes back up its stdout, and stderr is a log nobody was supposed to
have to read until something went wrong.

That single shared pipe is the whole design problem. Answers come back in
whichever order the server finished them, notifications arrive between them
belonging to whichever request provoked them, and a server that dies takes every
outstanding request with it. The correlator
(L<MCP::Client::Correlator>) owns the first two; this class owns the third, and
is written on the assumption that the server will misbehave.

=head2 There is no shell

C<$command> is executed directly through C<Proc::Async>. Nothing is ever passed
to C<sh> or C<cmd.exe>, so there is no quoting to get wrong, no glob expansion,
no C<$(...)>, and no injection: an argument containing C<; rm -rf /> is one
argument containing that text. Two consequences worth knowing:

=item B<No C<PATH> extension magic on Windows.> C<npx> is C<npx.cmd>, and a
      C<.cmd> shim cannot be executed without a shell — name the real
      executable, or the C<.cmd> explicitly and accept that Windows will resolve
      it as a batch file only if the OS can.
=item B<NUL bytes are refused.> A C<\0> in the command, an argument, or an
      environment entry cannot survive the syscall boundary intact, so it is
      rejected up front with C<X::MCP::Client::SpawnFailed> rather than silently
      truncating what the child receives.

=head2 The environment

By default the child inherits this process's environment and C<%env> is layered
on top of it, because a server that cannot see C<PATH> or C<HOME> usually cannot
start. Pass C<:!inherit-env> for a server that should see C<%env> and nothing
else:

=begin code :lang<raku>
# PATH, HOME and friends, plus the token
MCP::Client::Transport::Stdio.new(:command<srv>, env => { TOKEN => 'abc' });

# exactly one variable, and nothing else
MCP::Client::Transport::Stdio.new(:command<srv>, env => { TOKEN => 'abc' }, :!inherit-env);
=end code

=head2 Failure, and how it reaches you

Every way this can go wrong has a typed exception and a bounded wait; nothing
here can hang:

=item B<The command will not start> — a missing executable, a working directory
      that does not exist, a C<.cmd> shim. C<X::MCP::Client::SpawnFailed>,
      raised on the first request (the spawn result arrives in milliseconds, so
      "the first request" is not a wait) and on every request after it.
=item B<The child dies with work outstanding> —
      C<X::MCP::Client::ServerGone>, carrying the exit code, the signal, and the
      tail of the child's stderr, which for a misconfigured server is the entire
      diagnosis. Everything outstanding fails together, and requests made
      afterwards fail immediately rather than waiting for a server that is not
      coming back.
=item B<A request outlives its budget> — C<X::MCP::Client::Timeout>. The
      B<connection survives>: the request stops being tracked, a late answer for
      it is dropped, and the next request goes out normally.
=item B<C<close>> — C<X::MCP::Client::TransportClosed> for anything still in
      flight, and for anything attempted afterwards.
=item B<A line that is not JSON-RPC> — dropped, reported through C<:&on-log>,
      and otherwise ignored. Servers print banners, deprecation warnings and
      progress bars to stdout; one of them must never kill a session.

=begin code :lang<raku>
{
	CATCH {
		when X::MCP::Client::ServerGone {
			note "server died (exit {.exit-code // '?'}): {.stderr-tail}";
		}
		when X::MCP::Client::Timeout { note 'still connected, just slow' }
	}
	$mcp.call-tool('slow', {});
}
=end code

=head2 Notifications

A stdio server has one channel for everything, so a notification arrives with no
indication of which request it belongs to. This transport delivers each one
exactly once, to whichever of these applies first:

=item the C<&on-notification> of the single outstanding request, when exactly
      one request is in flight — the common case, and the only one where the
      attribution is knowable;
=item otherwise the first C<&on-notification> the transport was ever handed,
      which for C<MCP::Client> is a connection-wide sink and therefore the right
      place for a notification that cannot be attributed.

Everything is also published on C<notifications>, a C<Supply> a direct user of
the transport can tap without going through a client:

=begin code :lang<raku>
$wire.notifications.tap: -> %note { say "server said %note<method>" };
=end code

=head2 Server-initiated requests

A legacy-era server may turn round and ask the client something (sampling,
elicitation, roots). Those arrive as JSON-RPC I<requests> on the same pipe, and
this transport answers every one of them with C<-32601 METHOD_NOT_FOUND>: the
2026-07-28 era does that work through the multi round-trip loop in
C<MCP::Client>, which is where the caller's hooks live, and inventing a second
path for it here would put the same decision in two places. The refusal is
reported through C<:&on-log>.

=head2 Shutting down

C<close> is deliberate and bounded: stdin is closed (which is how a well-behaved
MCP server is asked to stop), the child is given C<:$kill-grace> seconds to
exit, and is then C<SIGKILL>ed. Whatever is still outstanding fails with
C<X::MCP::Client::TransportClosed>. It is idempotent, and safe on a connection
whose child died an hour ago.

=end pod

use MCP::Server::Protocol;

use MCP::Client::Correlator;
use MCP::Client::Exceptions;
use MCP::Client::Protocol;
use MCP::Client::Transport;

unit class MCP::Client::Transport::Stdio does MCP::Client::Transport;

# How long the reader is allowed to keep draining stdout and stderr after the
# child has exited. Without a bound, a grandchild holding the pipes open would
# keep the connection's failure from ever being reported; with one, the last
# lines a dying server wrote are still in the ServerGone message.
constant DRAIN-GRACE = 2;

#| The program to run. Executed directly — see the note about shells above.
has Str:D $.command is required;

#| Its arguments, passed through verbatim.
has @.args;

#| Environment entries for the child. Layered over this process's environment
#| unless C<:!inherit-env>.
has %.env;

#| Working directory for the child. Must exist: a missing one is
#| C<X::MCP::Client::SpawnFailed> at construction rather than a confusing OS
#| error later.
has Str $.cwd;

#| Whether the child inherits this process's environment.
has Bool:D $.inherit-env = True;

#| Seconds a request waits when the caller names no budget of its own. C<0>
#| means "wait forever", which only makes sense when the caller is managing
#| cancellation itself.
has Real:D $.default-timeout = 60;

#| Seconds C<close> waits for the child to exit before killing it, and again
#| after the kill.
has Real:D $.kill-grace = 5;

#| How many lines of the child's stderr to keep for the C<ServerGone> message.
has UInt:D $.stderr-lines = 50;

#| Called with each line the child writes to stderr, as it arrives. The ring
#| buffer is kept regardless; this is for a caller that wants the server's log
#| live rather than only post mortem.
has &.on-stderr;

#| Called with a one-line diagnostic when the transport papers over something:
#| a line of stdout that was not JSON-RPC, a late answer to a request that had
#| already given up, a server-initiated request that was refused. Undefined by
#| default — a library that writes to C<$*ERR> uninvited is worse than one that
#| is quiet — but wiring it is the difference between diagnosing a chatty server
#| in a minute and in an afternoon.
has &.on-log;

has Str    @!argv;
has        %!environment;
has Bool   $!custom-env = False;
has Proc::Async $!proc;
has Promise $!exited;
has Promise $!pump;
has MCP::Client::Correlator $!correlator;
has Lock   $!lock .= new;
has Lock   $!write-lock .= new;
has        %!listeners;
has        $!connection-sink;
has Str    @!stderr-ring;
has Bool   $!closing = False;
has Bool   $!closed = False;
has Bool   $!gone = False;
has Bool   $!notifications-done = False;
has Int    $!exit-code;
has Int    $!signal;
has Supplier $!notifications .= new;

submethod TWEAK(--> Nil) {
	self!validate;
	$!correlator = MCP::Client::Correlator.new(default-timeout => $!default-timeout);
	self!spawn;
}

# === The role ===

#| Send one request and promise its answer. See L<MCP::Client::Transport> for
#| the contract; everything here is an implementation of it.
method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
	my $id = %msg<id>;
	return Promise.broken(X::MCP::Client::Protocol.new(
		detail => 'a request handed to the stdio transport carried no id',
	)) unless $id.defined;

	my $method = %msg<method> ~~ Str:D ?? %msg<method> !! Str;

	return Promise.broken(X::MCP::Client::TransportClosed.new(
		detail => "the connection to '$!command' is closed",
	)) if $!lock.protect: { $!closed };

	with $cancelled {
		return Promise.broken(X::MCP::Client::Cancelled.new(:$id, :$method))
			if .status ~~ Kept;
	}

	my Real $budget = $timeout ~~ Real:D ?? $timeout.Real !! $!default-timeout;

	# register throws on a duplicate id, which is a caller bug rather than a
	# server condition -- but the role promises a Promise, not an exception, so
	# it comes back as a broken one either way.
	my $answer;
	{
		CATCH { default { $answer = Promise.broken($_) } }
		$answer = $!correlator.register($id, :$method, timeout => $budget);
	}

	# A correlator that has already been retired by a dead child hands back a
	# broken promise without registering anything; there is nothing to send.
	return $answer if $answer.status ~~ Broken;

	$!lock.protect: {
		if &on-notification {
			%!listeners{$id} = &on-notification;
			$!connection-sink //= &on-notification;
		}
	}
	$answer.then({ self!forget($id) });

	with $cancelled {
		.then(-> $settled {
			$settled.cause if $settled.status ~~ Broken;
			$!correlator.cancel($id);
		});
	}

	self!send(format-message(%msg), $id);
	$answer;
}

#| Send one notification. Fire and forget: a delivery failure is reported
#| through C<:&on-log> and never thrown at the caller.
method notify(%msg --> Nil) {
	return if $!lock.protect: { $!closed };
	self!send(format-message(%msg));
}

#| Close stdin, give the child C<:$kill-grace> seconds to exit, kill it if it
#| does not, and fail everything outstanding with
#| C<X::MCP::Client::TransportClosed>. Idempotent.
method close(--> Nil) {
	my $already = $!lock.protect: {
		my $was = $!closed;
		$!closing = True;
		$!closed = True;
		$was;
	};
	return if $already;

	# Closing stdin is how a stdio MCP server is asked to stop: its read loop
	# sees EOF and returns. Everything after this is escalation.
	{
		CATCH { default { self!note('closing stdin failed: ' ~ .message.lines.head) } }
		$!proc.close-stdin;
	}

	await Promise.anyof($!exited, Promise.in($!kill-grace));

	if $!exited.status ~~ Planned {
		# SIGKILL rather than TERM-then-KILL: Rakudo ignores every .kill after the
		# first on a given Proc::Async, so a catchable signal first would leave no
		# way to escalate against a child that traps it. It is also the portable
		# choice -- one of the three signals libuv maps onto TerminateProcess.
		{
			CATCH { default { self!note('killing the server failed: ' ~ .message.lines.head) } }
			$!proc.kill(Signal::SIGKILL);
		}
		await Promise.anyof($!exited, Promise.in($!kill-grace));
	}

	# Let the reader finish first: a server that answered and then exited has its
	# last responses somewhere in the pipe, and correlating them is better than
	# failing requests that were in fact answered.
	await Promise.anyof($!pump, Promise.in(DRAIN-GRACE)) with $!pump;

	$!correlator.fail-all(X::MCP::Client::TransportClosed.new(
		detail => "the connection to '$!command' was closed",
	));
	$!lock.protect: { $!gone = True };
	self!finish-notifications;
}

#| False once the child has gone or C<close> has been called. Advisory: a True
#| here is not a promise that the next request will be answered.
method alive(--> Bool) {
	$!lock.protect: { !$!closed && !$!gone }
}

# === Diagnostics ===

#| Every notification the server sent, whoever it was for. Taps see nothing that
#| arrived before they tapped.
method notifications(--> Supply:D) {
	$!notifications.Supply;
}

#| The child's exit code once it has exited, Nil while it is running.
method exit-code(--> Int) {
	$!lock.protect: { $!exit-code }
}

#| The signal that killed the child, if one did.
method signal(--> Int) {
	$!lock.protect: { $!signal }
}

#| The last C<:$stderr-lines> lines the child wrote to stderr, oldest first.
method stderr-tail(--> Str:D) {
	$!lock.protect: { @!stderr-ring.join("\n") }
}

#| How many requests are waiting for an answer.
method pending-count(--> Int:D) {
	$!correlator.pending-count;
}

#| The process id of the child, for a caller that wants to report it.
method pid() {
	$!proc.defined ?? $!proc.pid !! Nil;
}

# === Spawning ===

method !validate(--> Nil) {
	self!refuse('the command is empty') unless $!command.chars;
	self!refuse('the command contains a NUL byte') if $!command.contains("\0");

	for @!args.kv -> $index, $arg {
		self!refuse("argument $index is a {$arg.^name}, not a string")
			unless $arg ~~ Str:D || ($arg ~~ Numeric:D && $arg !~~ Bool);
		my Str $value = $arg.Str;
		self!refuse("argument $index contains a NUL byte") if $value.contains("\0");
		@!argv.push: $value;
	}

	for %!env.kv -> $key, $value {
		self!refuse("the environment variable name '$key' contains a NUL byte")
			if $key.contains("\0");
		self!refuse("the value of environment variable '$key' is a {$value.^name}, not a string")
			unless $value ~~ Str:D || ($value ~~ Numeric:D && $value !~~ Bool);
		self!refuse("the value of environment variable '$key' contains a NUL byte")
			if $value.Str.contains("\0");
	}

	# Passed to the child only when the caller asked for something other than
	# "whatever this process has": an explicitly empty environment is a request
	# in its own right, and is not the same as saying nothing.
	$!custom-env = %!env.elems > 0 || !$!inherit-env;
	if $!custom-env {
		%!environment = $!inherit-env ?? %*ENV.Hash !! {};
		%!environment{.key} = .value.Str for %!env.pairs;
	}

	with $!cwd {
		self!refuse("the working directory '$_' does not exist") unless .IO.d;
	}
}

method !refuse(Str:D $detail) {
	die X::MCP::Client::SpawnFailed.new(
		command => $!command, args => @!argv, :$detail,
	);
}

method !spawn(--> Nil) {
	$!proc = Proc::Async.new($!command, |@!argv, :w);

	my $out-drained = Promise.new;
	my $err-drained = Promise.new;

	# Quit handlers on every tap are load-bearing: when a spawn fails, both
	# output supplies quit with the spawn exception, and an unhandled quit runs
	# on a scheduler thread -- which would take the host process down instead of
	# breaking the promises we are about to fail deliberately.
	$!proc.stdout.lines.tap(
		-> $line { self!inbound($line) },
		done => { self!settle($out-drained) },
		quit => -> $ex { self!settle($out-drained) },
	);
	$!proc.stderr.lines.tap(
		-> $line { self!stderr-line($line) },
		done => { self!settle($err-drained) },
		quit => -> $ex { self!settle($err-drained) },
	);

	$!exited = $!proc.start(
		|($!cwd.defined ?? (cwd => $!cwd) !! ()),
		|($!custom-env ?? (ENV => %!environment) !! ()),
	);

	$!pump = start {
		# Both conditions, not just the exit: a server that answers and then
		# exits immediately has its last response somewhere in the pipe, and
		# failing the request it belongs to would be a lie. The second branch
		# bounds that wait for the case where a grandchild is holding the pipes.
		await Promise.anyof(
			Promise.allof($!exited, $out-drained, $err-drained),
			$!exited.then(-> $settled {
				$settled.cause if $settled.status ~~ Broken;
				await Promise.in(DRAIN-GRACE);
			}),
		);
		self!child-gone;
	};
}

# A tap's done and quit handlers are mutually exclusive, so this can only fire
# once per promise -- but it is cheap to be sure, and keeping a broken vow out of
# the reader is worth more than the branch costs.
method !settle(Promise:D $promise --> Nil) {
	CATCH { default { } }
	$promise.keep(True) if $promise.status ~~ Planned;
}

# === Reading ===

method !inbound(Str:D $line --> Nil) {
	CATCH {
		default {
			# The read loop is the one thread that must never die: everything
			# outstanding is waiting on it.
			self!note('the reader survived an error: ' ~ .message.lines.head);
		}
	}

	my %in = parse-inbound($line);

	given %in<kind> {
		when 'response' {
			# A response whose id is JSON null answers nothing: it is what a
			# server sends when it could not parse our line well enough to know
			# what it was answering. There is no promise to settle, and looking
			# one up under an undefined key would only make noise.
			if %in<id>.defined {
				%in<error>:exists
					?? self!answer-error(%in)
					!! self!answer-result(%in);
			}
			else {
				self!note('the server answered with a null id, which correlates '
					~ 'with nothing: ' ~ self!abbreviate($line));
			}
		}
		when 'notification' { self!deliver-notification(%in) }
		when 'request'      { self!refuse-server-request(%in) }
		default             { self!note("dropped a line of stdout ({%in<reason>}): "
									~ self!abbreviate($line)) }
	}
}

method !answer-error(%in --> Nil) {
	my %error = %in<error> ~~ Associative ?? %in<error>.Hash !! {};
	my $delivered = $!correlator.reject(%in<id>, X::MCP::Client::Protocol.new(
		detail => (%error<message> ~~ Str:D ?? %error<message> !! 'server error'),
		code   => (%error<code> ~~ Real:D ?? %error<code>.Int !! Int),
		data   => %error<data>,
	));
	self!note("dropped a late error for request {%in<id>}") unless $delivered;
}

method !answer-result(%in --> Nil) {
	my $delivered = $!correlator.resolve(%in<id>, normalize-result(%in<result>));
	self!note("dropped a late answer for request {%in<id>}") unless $delivered;
}

# One pipe carries every conversation, so a notification says nothing about
# which request provoked it. Delivered to the sole request in flight when there
# is exactly one -- the only case where the attribution is knowable -- and to the
# connection-wide sink otherwise. Exactly once, either way.
method !deliver-notification(%in --> Nil) {
	my %note = method => %in<method>, params => %in<params>;

	{
		CATCH { default { } }
		$!notifications.emit(%note) unless $!lock.protect: { $!notifications-done };
	}

	my $sink = $!lock.protect: {
		my @live = %!listeners.values;
		@live.elems == 1 ?? @live[0] !! $!connection-sink;
	};
	return without $sink;

	CATCH { default { self!note('a notification subscriber threw: ' ~ .message.lines.head) } }
	$sink(%note);
}

# A legacy server may ask the client for sampling, elicitation or a root list on
# this same pipe. Answering "no such method" is honest: the 2026-07-28 loop in
# MCP::Client is where the caller's hooks are wired, and it reaches them through
# results rather than through server-initiated requests.
method !refuse-server-request(%in --> Nil) {
	my $method = %in<method> // '';
	self!note("refused a server-initiated '$method' request: "
		~ 'this client answers input requests through the 2026-07-28 loop, '
		~ 'not through server-initiated JSON-RPC requests');
	self!send(format-message(
		error-response(%in<id>, METHOD_NOT_FOUND, "Method not found: $method"),
	));
}

method !stderr-line(Str:D $line --> Nil) {
	$!lock.protect: {
		@!stderr-ring.push($line);
		@!stderr-ring.shift while @!stderr-ring.elems > $!stderr-lines;
	}

	return without &!on-stderr;
	CATCH { default { self!note('the stderr subscriber threw: ' ~ .message.lines.head) } }
	&!on-stderr($line);
}

# === Writing ===

method !send(Str:D $payload, $id? --> Nil) {
	my $written;
	{
		CATCH { default { $written = Promise.broken($_) } }
		$written = $!write-lock.protect: { $!proc.print($payload) };
	}

	$written.then(-> $settled {
		if $settled.status ~~ Broken {
			my $why = $settled.cause.message.lines.head;
			if $id.defined {
				$!correlator.reject($id, self!write-failure($why));
			}
			else {
				self!note("a message could not be written to the server: $why");
			}
		}
	});
}

# A write that fails means the child is gone, or going, or never arrived. Which
# of those it is decides which exception the caller should see -- and the reaper
# is the only part of this class that knows, so wait for its verdict rather than
# guessing, and guess only if it never comes. Called from a `.then` on the
# scheduler, never from the reader, so this waits on nobody's behalf but its own.
method !write-failure(Str:D $why --> Exception:D) {
	await Promise.anyof($!pump, Promise.in(DRAIN-GRACE)) with $!pump;
	with $!correlator.failure {
		return $_;
	}

	return X::MCP::Client::TransportClosed.new(
		detail => "the connection to '$!command' was closed while writing: $why",
	) if $!lock.protect: { $!closing };

	X::MCP::Client::ServerGone.new(
		command => $!command,
		exit-code => self.exit-code,
		signal => self.signal,
		stderr-tail => self.stderr-tail,
		detail => $why,
	);
}

# === Death ===

method !child-gone(--> Nil) {
	CATCH { default { self!note('the reaper failed: ' ~ .message.lines.head) } }

	my $failure;

	if $!exited.status ~~ Broken {
		# The command never ran at all: no exit code, no stderr, just the OS
		# saying no. Reporting this as ServerGone would send the caller looking
		# for a server that was never there.
		$failure = X::MCP::Client::SpawnFailed.new(
			command => $!command,
			args    => @!argv,
			detail  => $!exited.cause.message.lines.head,
		);
	}
	else {
		my $result = $!exited.result;
		$!lock.protect: {
			$!exit-code = $result.exitcode;
			# Zero is "no signal was involved", which is a different statement
			# from "it was killed by signal 0" -- report it as the absence it is.
			$!signal = $result.signal != 0 ?? $result.signal !! Int;
		}

		$failure = $!lock.protect({ $!closing })
			?? X::MCP::Client::TransportClosed.new(
					detail => "the connection to '$!command' was closed",
				)
			!! X::MCP::Client::ServerGone.new(
					command     => $!command,
					exit-code   => self.exit-code,
					signal      => self.signal,
					stderr-tail => self.stderr-tail,
				);
	}

	$!lock.protect: { $!gone = True };
	$!correlator.fail-all($failure);
	self!finish-notifications;
}

method !finish-notifications(--> Nil) {
	my $first = $!lock.protect: {
		my $was = $!notifications-done;
		$!notifications-done = True;
		!$was;
	};
	return unless $first;

	CATCH { default { } }
	$!notifications.done;
}

# === Bookkeeping ===

method !forget($id --> Nil) {
	$!lock.protect: { %!listeners{$id}:delete };
}

method !note(Str:D $message --> Nil) {
	return without &!on-log;
	CATCH { default { } }   # a diagnostic sink that throws is not worth a crash
	&!on-log($message);
}

method !abbreviate(Str:D $line --> Str:D) {
	my $clean = $line.trim;
	$clean.chars > 120 ?? $clean.substr(0, 117) ~ '...' !! $clean;
}
