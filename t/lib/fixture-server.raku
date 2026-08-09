#!/usr/bin/env raku

=begin pod

=head1 NAME

fixture-server.raku - a real MCP server on stdio, for the stdio transport tests

=head1 SYNOPSIS

=begin code :lang<shell>
raku -Ilib -It/lib -I../MCP-Server/lib t/lib/fixture-server.raku --era=both
=end code

=head1 DESCRIPTION

C<t/08> and C<t/09> spawn this with C<$*EXECUTABLE>, passing through whatever
C<-I> paths the test process itself is using, so it works both from a checkout
(C<prove6 -Ilib -It/lib -I../MCP-Server/lib t/>) and against installed
dependencies (C<prove6 -I. t>, which is what CI does).

It serves C<MCP::Client::Test::TestKit> plus a handful of tools that only make
sense in a subprocess — a gate that proves two requests were in flight at once,
a tool that prints garbage to stdout, and a tool that kills the process
mid-request.

=head2 Why not MCP::Server.run

C<MCP::Server.run> is a strictly serial loop: read a line, dispatch it, write
the answer, read the next line. That is a perfectly good MCP server, but it
cannot demonstrate the thing the client's correlator exists for — answers
arriving in a different order from the questions — because a slow request blocks
the loop that would have answered a fast one.

So the loop here dispatches each message on its own thread and writes answers
under a lock. Everything else is the real server: the era is detected per
message (C<detect-era>), modern requests go through C<handle-modern-request> so
their notifications reach the client on the same pipe, and legacy ones go
through C<handle-request>.

One deliberate gap: client notifications (C<notifications/initialized>) are
accepted and dropped rather than fed to the server's private notification
handler, which C<run> reaches and a custom loop cannot. The only thing that
depends on it is legacy-era server logging, which C<t/07> covers in-process.

=head2 Options

=item C<--era=both> — the default: both protocol eras, so the client's probe
      settles on modern.
=item C<--era=modern> — modern only.
=item C<--era=legacy> — legacy only. C<server/discover> still answers (it is the
      bootstrap probe and is exempt from the version gate) but its
      C<supportedVersions> is empty, which is the server's way of saying "talk
      to me the old way"; the client then falls back to C<initialize>.

=end pod

use MCP::Server;
use MCP::Server::Protocol;
use MCP::Client::Test::TestKit;

sub MAIN(Str :$era = 'both') {
	my @versions = do given $era {
		when 'both'   { SUPPORTED-PROTOCOL-VERSIONS.list }
		when 'modern' { (MODERN-PROTOCOL-VERSION,) }
		when 'legacy' { (LEGACY-PROTOCOL-VERSION,) }
		default {
			note "fixture-server: unknown --era '$era' (expected both, modern or legacy)";
			exit 2;
		}
	};

	my $out-lock = Lock.new;
	my sub write-line(Str:D $payload --> Nil) {
		$out-lock.protect: {
			$*OUT.print($payload);
			$*OUT.flush;
		}
	}

	my $server = MCP::Server.new(
		name => 'fixture-server',
		version => '0.1.0',
		instructions => 'A fixture, not a product',
		protocol-versions => @versions,
	);
	$server.plug(MCP::Client::Test::TestKit.new(slow-ms => 250));

	# --- The gate: proof that two requests were in flight at once ---------------
	#
	# gate_wait blocks until gate_open releases it, and reports whether it
	# actually had to block. gate_open waits until gate_wait has arrived before
	# releasing, so the pair can only both complete if the server was handling
	# them concurrently -- with a serial loop, gate_open would never be
	# dispatched and both would give up on their safety timers.
	my $gate = Promise.new;
	my $arrived = Promise.new;
	my $gate-lock = Lock.new;
	my sub open-gate(Promise:D $promise --> Nil) {
		$gate-lock.protect: { $promise.keep(True) if $promise.status ~~ Planned };
	}
	constant GATE-SAFETY = 30;

	$server.tool: 'gate_wait',
		description => 'Block until gate_open is called',
		handler => -> :%args {
			# Read the gate before announcing our arrival, not after: gate_open
			# cannot possibly have opened it yet, so "did I have to block?" is
			# decided rather than raced.
			my $blocked = $gate.status ~~ Planned;
			open-gate($arrived);
			await Promise.anyof($gate, Promise.in(GATE-SAFETY));
			$gate.status ~~ Planned
				?? 'gave up waiting'
				!! ($blocked ?? 'waited' !! 'immediate');
		};

	$server.tool: 'gate_open',
		description => 'Release whoever is waiting on the gate',
		handler => -> :%args {
			# NB: no `return` anywhere in a pointy block -- it is a Block, not a
			# Routine, and returning from one outside its dynamic scope dies.
			await Promise.anyof($arrived, Promise.in(GATE-SAFETY));
			if $arrived.status ~~ Planned {
				'nobody was waiting';
			}
			else {
				open-gate($gate);
				'opened';
			}
		};

	# --- Misbehaviour on demand -------------------------------------------------

	$server.tool: 'banner',
		description => 'Print a line of non-JSON to stdout, then answer normally',
		params => { text => { type => 'string' } },
		handler => -> :%args {
			# Through the same lock as every response, so the banner is a whole
			# line of its own rather than a fragment wedged into one.
			write-line(((%args<text> // 'fixture-server v0.1.0 ready') ~ "\n"));
			'banner printed';
		};

	$server.tool: 'crash',
		description => 'Write to stderr and exit the process mid-request',
		params => {
			code => { type => 'integer' },
			message => { type => 'string' },
		},
		handler => -> :%args {
			my $code = %args<code> ~~ Real:D ?? %args<code>.Int !! 3;
			$*ERR.say(%args<message> // 'fixture-server: taking the pipe with me');
			$*ERR.flush;
			exit $code;
		};

	# --- The loop ---------------------------------------------------------------

	my sub handle(Str:D $line --> Nil) {
		CATCH {
			default {
				# A fixture that dies quietly is a test that hangs.
				$*ERR.say("fixture-server: handler failed: {.message}");
				$*ERR.flush;
			}
		}

		my %msg = parse-message($line);

		# parse-message answers a malformed line with a ready-made error response.
		if %msg<error>:exists {
			write-line(format-message(%msg));
			return;
		}

		# JSON-RPC forbids answering a notification.
		return unless %msg<id>:exists;

		my %response = detect-era(%msg) eq 'modern'
			?? $server.handle-modern-request(
					%msg, notify => -> %note { write-line(format-message(%note)) },
				)
			!! $server.handle-request(%msg);

		write-line(format-message(%response)) if %response.elems;
	}

	# Stdin closing is how a stdio MCP server is told to stop. Work already in
	# flight gets a short grace to finish and answer; anything still running when
	# that runs out is abandoned, exactly as a real server abandons it.
	constant SHUTDOWN-GRACE = 2;
	my $tracker = Lock.new;
	my @in-flight;

	for $*IN.lines -> $line {
		next unless $line.trim.chars;
		my $work = start handle($line);
		$tracker.protect: {
			# Pruned as we go so a long session does not accumulate one settled
			# Promise per message.
			@in-flight = @in-flight.grep({ .status ~~ Planned });
			@in-flight.push($work);
		}
	}

	my @unfinished = $tracker.protect: { @in-flight.grep({ .status ~~ Planned }).List };
	await Promise.anyof(Promise.allof(@unfinished), Promise.in(SHUTDOWN-GRACE)) if @unfinished;
}
