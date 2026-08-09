=begin pod

=head1 NAME

MCP::Client::Exceptions - the typed failures thrown by MCP::Client

=head1 DESCRIPTION

Every failure this distribution raises on its own behalf is an
C<X::MCP::Client>, so one C<CATCH> clause separates "the MCP conversation went
wrong" from "the code around it went wrong". The subclasses carry the context
you would otherwise have to scrape back out of a message string: the exit code
and last words of a server process that died, the version list a server said it
would accept, the JSON-RPC error code and C<data> payload the server sent.

=head2 The failures

=item C<X::MCP::Client::Timeout> — a request outlived its budget. Carries
      C<seconds>, and C<method>/C<id> when the caller registered them.
=item C<X::MCP::Client::ServerGone> — the server process exited (or the HTTP
      connection died) with requests in flight. Carries C<exit-code>,
      C<signal>, C<command> and C<stderr-tail>, the tail of the child's stderr
      ring buffer — which is usually the only place the real reason is written.
=item C<X::MCP::Client::Protocol> — the peer said something the protocol does
      not allow, or answered with a JSON-RPC error. Carries C<code> and the
      verbatim C<data> payload when it came off the wire.
=item C<X::MCP::Client::UnsupportedVersion> — no overlap between the versions
      we speak and the versions the server speaks. Carries C<requested> and
      C<supported>.
=item C<X::MCP::Client::Cancelled> — a request was abandoned by the caller.
=item C<X::MCP::Client::InputLoopExceeded> — a multi round-trip request kept
      asking for input past C<max-input-rounds>.
=item C<X::MCP::Client::TransportClosed> — the transport was closed, either by
      C<close> or by a failure that took the connection with it.
=item C<X::MCP::Client::SpawnFailed> — the server command could not be started.

=head1 EXAMPLES

Distinguish "this server is broken" from "this call is slow":

=begin code :lang<raku>
use MCP::Client::Exceptions;

{
	CATCH {
		when X::MCP::Client::Timeout {
			note "gave up on {.method // 'request'} after {.seconds}s";
		}
		when X::MCP::Client::ServerGone {
			note "server died (exit {.exit-code // '?'})";
			note "  last words: {.stderr-tail}" if .stderr-tail.chars;
		}
		when X::MCP::Client {
			note "MCP failure: {.^name}: {.message}";
		}
	}
	# ... an MCP::Client call ...
}
=end code

Read the machine-readable half of a protocol error rather than its message:

=begin code :lang<raku>
CATCH {
	when X::MCP::Client::Protocol {
		if .code == -32022 {   # UNSUPPORTED_PROTOCOL_VERSION
			note "server offers: " ~ (.data<supported> // []).join(', ');
		}
	}
}
=end code

=end pod

unit module MCP::Client::Exceptions;

#| Base class for every failure raised by MCP::Client. Throwable on its own with
#| a C<detail> string, but the subclasses below are what you normally see.
class X::MCP::Client is Exception is export {
	has Str $.detail;

	method message(--> Str:D) {
		$!detail // 'MCP client error';
	}
}

#| A request outlived its timeout budget. The request is no longer tracked when
#| this is thrown: a late answer for it is dropped, not delivered.
class X::MCP::Client::Timeout is X::MCP::Client is export {
	has Real:D $.seconds is required;
	has Str    $.method;
	has        $.id;

	method message(--> Str:D) {
		'MCP request timed out after ' ~ $!seconds ~ 's'
			~ ($!method.defined ?? " (method '$!method')" !! '')
			~ ($!id.defined ?? " (id $!id)" !! '');
	}
}

#| The server went away with work outstanding. C<stderr-tail> is the tail of
#| whatever the child wrote to stderr before dying, which for a misconfigured
#| server ("no such module", "missing API key") is the entire diagnosis.
class X::MCP::Client::ServerGone is X::MCP::Client is export {
	has Int  $.exit-code;
	has Int  $.signal;
	has Str  $.command;
	has Str:D $.stderr-tail = '';

	method message(--> Str:D) {
		my $what = $!command.defined ?? "MCP server '$!command'" !! 'MCP server';
		my $how = do {
			if $!signal.defined && $!signal != 0 { "was killed by signal $!signal" }
			elsif $!exit-code.defined            { "exited with code $!exit-code" }
			else                                 { 'is gone' }
		};
		my $tail = $!stderr-tail.trim;
		"$what $how" ~ ($tail.chars ?? ": $tail" !! '');
	}
}

#| The peer broke the protocol, or answered a request with a JSON-RPC error.
#| C<code> and C<data> are the wire values when there was an error object;
#| C<data> is passed through verbatim so callers can read server-defined fields.
class X::MCP::Client::Protocol is X::MCP::Client is export {
	has Str:D $.detail is required;
	has Int   $.code;
	has       $.data;

	method message(--> Str:D) {
		'MCP protocol error: ' ~ $!detail ~ ($!code.defined ?? " (code $!code)" !! '');
	}
}

#| Version negotiation found no common ground. C<supported> is what the server
#| said it speaks (empty when it never told us), C<requested> what we wanted.
class X::MCP::Client::UnsupportedVersion is X::MCP::Client is export {
	has     $.requested;
	has     @.supported;

	method message(--> Str:D) {
		'Unsupported MCP protocol version'
			~ ($!requested.defined ?? " '$!requested'" !! '')
			~ (@!supported.elems
				?? '; server supports: ' ~ @!supported.join(', ')
				!! '; server named no supported versions');
	}
}

#| The caller abandoned a request. Distinct from a timeout: nothing failed, the
#| answer simply stopped being wanted.
class X::MCP::Client::Cancelled is X::MCP::Client is export {
	has Str $.method;
	has     $.id;

	method message(--> Str:D) {
		'MCP request cancelled'
			~ ($!method.defined ?? " (method '$!method')" !! '')
			~ ($!id.defined ?? " (id $!id)" !! '');
	}
}

#| A 2026-07-28 multi round-trip request asked for client input more times than
#| the configured budget allows. Raising this rather than looping forever is
#| deliberate: a server that never converges must not be able to pin a client.
class X::MCP::Client::InputLoopExceeded is X::MCP::Client is export {
	has UInt:D $.rounds is required;
	has Str    $.method;

	method message(--> Str:D) {
		"MCP request" ~ ($!method.defined ?? " '$!method'" !! '')
			~ " still wanted input after $!rounds round(s)";
	}
}

#| The transport is closed. Requests made after C<close>, and requests still in
#| flight when the connection is torn down deliberately, fail with this.
class X::MCP::Client::TransportClosed is X::MCP::Client is export {
	method message(--> Str:D) {
		'MCP transport is closed' ~ ($.detail.defined ?? ": $.detail" !! '');
	}
}

#| The server command could not be started at all — a missing executable, a
#| bad working directory, a Windows C<.cmd> shim that needs a shell we never
#| use. C<detail> quotes the underlying OS error.
class X::MCP::Client::SpawnFailed is X::MCP::Client is export {
	has Str:D $.command is required;
	has Str   @.args;

	method message(--> Str:D) {
		my $cmd = ($!command, |@!args).join(' ');
		"Failed to start MCP server '$cmd'" ~ ($.detail.defined ?? ": $.detail" !! '');
	}
}
