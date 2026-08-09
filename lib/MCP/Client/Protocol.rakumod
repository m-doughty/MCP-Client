=begin pod

=head1 NAME

MCP::Client::Protocol - the client half of the MCP wire format

=head1 DESCRIPTION

L<MCP::Server::Protocol> owns everything both ends of an MCP conversation
agree on: the version constants, the JSON-RPC and 2026-07-28 error codes, the
C<_meta> key names, C<format-message>. This module owns the half of the wire
that only a client needs, and that the server module deliberately does not
implement:

=item B<Outbound requests.> C<build-request> writes the request a server will
      classify into the era you asked for. A modern-era request carries the
      2026-07-28 C<params._meta> block (protocol version, and optionally client
      info, client capabilities and a per-request log level); a legacy request
      carries none of it.
=item B<Inbound messages.> C<parse-inbound> classifies anything a server can
      send us. The server's C<parse-message> rejects a message without a
      C<method> — which is every response ever sent to a client — so a client
      cannot use it.
=item B<Result shaping.> C<normalize-result> gives a legacy result the
      C<resultType> a modern one would have had, so one code path can read
      both. C<decline-input-response> writes the "no thank you" answer to a
      server-initiated input request. C<is-modern-error> recognises the error
      codes only a 2026-07-28 server emits, which is how the era probe tells a
      modern server from an ancient one.

Import L<MCP::Server::Protocol> alongside this module when you want the shared
constants; they are not re-exported from here.

=head1 EXAMPLES

Build a request for each era and see how a server would classify it:

=begin code :lang<raku>
use MCP::Server::Protocol;   # for detect-era, MODERN-PROTOCOL-VERSION
use MCP::Client::Protocol;

my %modern = build-request(
	1, 'tools/call', { name => 'echo', arguments => { text => 'hi' } },
	era         => 'modern',
	client-info => { name => 'my-agent', version => '1.0' },
	log-level   => 'info',
);
say %modern<params><_meta>{META-PROTOCOL-VERSION};  # 2026-07-28
say detect-era(%modern);                            # modern

my %legacy = build-request(
	2, 'tools/call', { name => 'echo', arguments => { text => 'hi' } },
	era => 'legacy',
);
say %legacy<params><_meta>:exists;                  # False
say detect-era(%legacy);                            # legacy
=end code

Classify whatever came back off the pipe. Nothing here throws on bad input —
a server that writes a stray line of log to stdout must not kill the read
loop:

=begin code :lang<raku>
given parse-inbound($line) -> %in {
	given %in<kind> {
		when 'response' {
			%in<error>:exists
				?? $correlator.reject(%in<id>, error-for(%in<error>))
				!! $correlator.resolve(%in<id>, normalize-result(%in<result>));
		}
		when 'notification' { $notifications.emit(%in) }
		when 'request'      { answer-server-request(%in) }
		when 'invalid'      { note "dropped inbound line: %in<reason>" }
	}
}
=end code

Decline a server-initiated input request, which is what the multi round-trip
loop does for every kind of input the caller has not wired a hook for. What
comes back is the I<value> half of one C<inputResponses> entry — the client
result that goes under the server's own key — because C<InputResponses> is a
map from the keys the server chose to bare client results:

=begin code :lang<raku>
my %responses;
for %result<inputRequests>.kv -> $key, %request {
	my $body = decline-input-response(%request);
	%responses{$key} = $body with $body;   # undefined means "omit this key"
}
# %responses = { github_login => { action => 'decline' } }
=end code

=end pod

use JSON::Fast;
use MCP::Server::Protocol;
use MCP::Client::Exceptions;

unit module MCP::Client::Protocol;

#| The two protocol eras, as a value: 'legacy' is 2025-11-25's initialize
#| handshake, 'modern' is 2026-07-28's stateless per-request _meta.
subset ClientEra is export of Str where 'legacy' | 'modern';

#| The classifications C<parse-inbound> tags a message with.
subset InboundKind is export of Str where 'response' | 'notification' | 'request' | 'invalid';

# 2026-07-28 result discriminants. A result is 'complete' unless the server is
# asking the client for something before it can finish (multi round-trip).
constant RESULT-TYPE-COMPLETE       is export = 'complete';
constant RESULT-TYPE-INPUT-REQUIRED is export = 'input_required';

#| The error codes that only exist in the 2026-07-28 era. Seeing any of them is
#| proof the peer is a modern server, whatever else it just refused to do.
constant MODERN-ERROR-CODES is export = (
	HEADER_MISMATCH,
	MISSING_REQUIRED_CLIENT_CAPABILITY,
	UNSUPPORTED_PROTOCOL_VERSION,
);

#| Build a JSON-RPC request in the given era.
#|
#| A modern request always carries C<params._meta>, because that block is
#| precisely what makes a server treat the request as modern (see
#| C<MCP::Server::Protocol::detect-era>): the protocol version is stamped on
#| every request, and client info, client capabilities and the per-request log
#| level are stamped when supplied. Any C<_meta> the caller put in %params (a
#| progress token, say) is preserved; the protocol keys win on collision.
#|
#| Client I<capabilities> are stamped whenever the caller passes them at all,
#| the empty hash included, and client I<info> only when it is non-empty. That
#| asymmetry is the spec's: 2026-07-28 marks
#| C<io.modelcontextprotocol/clientCapabilities> B<required> on every request
#| (a server rejects a request without it with -32602), and C<< {} >> is exactly
#| how a client that supports none of the optional client features declares
#| itself. C<io.modelcontextprotocol/clientInfo> is optional, so an empty one
#| is simply left out.
#|
#| A legacy request is passed through untouched — no C<_meta>, and no C<params>
#| key at all when there are no parameters.
#|
#| Throws X::MCP::Client::UnsupportedVersion if asked to stamp the legacy
#| version into a modern request (that combination is a contradiction, and a
#| server would answer it with -32022), and X::MCP::Client::Protocol for a log
#| level outside RFC 5424.
sub build-request(
	$id,
	Str:D $method,
	%params = {},
	ClientEra:D :$era!,
	Str :$protocol-version,
	:%client-info,
	:$client-capabilities,
	Str :$log-level,
	--> Hash
) is export {
	my %out = %params;

	if $era eq 'modern' {
		my $version = $protocol-version // MODERN-PROTOCOL-VERSION;
		die X::MCP::Client::UnsupportedVersion.new(
			requested => $version,
			supported => MODERN-PROTOCOL-VERSIONS.list,
		) if $version eq LEGACY-PROTOCOL-VERSION;

		if $log-level.defined && !(%LOG-LEVELS{$log-level}:exists) {
			die X::MCP::Client::Protocol.new(
				detail => "unknown log level '$log-level'"
					~ ' (expected one of ' ~ %LOG-LEVELS.keys.sort.join(', ') ~ ')',
			);
		}

		my %meta = %out<_meta> ~~ Associative ?? %out<_meta>.Hash !! {};
		%meta{META-PROTOCOL-VERSION} = $version;
		%meta{META-CLIENT-INFO} = %client-info.Hash if %client-info.elems > 0;
		%meta{META-CLIENT-CAPABILITIES} = $client-capabilities.Hash
			if $client-capabilities ~~ Associative;
		%meta{META-LOG-LEVEL} = $log-level if $log-level.defined;
		%out<_meta> = %meta;
	}

	my %msg = jsonrpc => '2.0', id => $id, method => $method;
	%msg<params> = %out if %out.elems > 0;
	%msg;
}

#| Classify one inbound line. Never throws and never dies on hostile input:
#| a read loop feeds this everything the server writes, including the stray
#| banner lines badly-behaved servers print to stdout, and a client that dies
#| on one of those is a client that cannot be shipped.
#|
#| The returned hash always has C<kind> and C<raw> (the line as received), and
#| C<message> (the decoded object) whenever the line was JSON at all:
#|
#| =item 'response'     — C<id> plus exactly one of C<result> / C<error>.
#| =item 'notification' — C<method> and C<params> (C<< {} >> when absent).
#| =item 'request'      — C<id>, C<method>, C<params>: the server asking us
#|                        something (sampling, elicitation, roots).
#| =item 'invalid'      — C<reason> says what was wrong with it.
#|
#| A response's C<result> is passed through verbatim, including JSON C<null>;
#| run it through C<normalize-result> before reading fields off it.
my sub invalid(Str:D $reason, Str:D $raw, $message? --> Hash) {
	my %out = kind => 'invalid', :$reason, :$raw;
	%out<message> = $message.Hash if $message ~~ Associative;
	%out;
}

sub parse-inbound(Str:D $line --> Hash) is export {
	my $trimmed = $line.trim;
	return invalid('blank line', $line) unless $trimmed.chars;

	# Every JSON-RPC message is an object, so a line that does not open with a
	# brace cannot be one. Saying so here rather than in the parser keeps the
	# banner lines and log spew that servers print to stdout off the JSON path
	# entirely — which is both faster and a better diagnosis than whatever the
	# parser would have said about the third character.
	return invalid('not a JSON object', $line) unless $trimmed.starts-with('{');

	my $decoded;
	{
		CATCH {
			default {
				return invalid('malformed JSON: ' ~ .message.lines.head, $line);
			}
		}
		$decoded = from-json($trimmed);
	}

	return invalid('not a JSON object', $line) unless $decoded ~~ Associative;

	my %msg = $decoded.Hash;
	return invalid('missing or wrong jsonrpc version', $line, %msg)
		unless (%msg<jsonrpc>:exists) && %msg<jsonrpc> ~~ Str:D && %msg<jsonrpc> eq '2.0';

	my %params = %msg<params> ~~ Associative ?? %msg<params>.Hash !! {};

	if %msg<method> ~~ Str:D {
		# A request needs a usable id; JSON null is not one. Rather than reject
		# such a message outright we read it as the notification it is shaped
		# like, because that is the only thing a client could usefully do with
		# it, and some servers do emit "id": null on notifications.
		return {
			kind => 'request', id => %msg<id>, method => %msg<method>,
			params => %params, raw => $line, message => %msg,
		} if (%msg<id>:exists) && %msg<id>.defined;

		return {
			kind => 'notification', method => %msg<method>,
			params => %params, raw => $line, message => %msg,
		};
	}

	return invalid('neither a method nor an id', $line, %msg) unless %msg<id>:exists;

	if %msg<error>:exists {
		return invalid('error is not an object', $line, %msg)
			unless %msg<error> ~~ Associative;
		return {
			kind => 'response', id => %msg<id>, error => %msg<error>.Hash,
			raw => $line, message => %msg,
		};
	}

	return invalid('response has neither result nor error', $line, %msg)
		unless %msg<result>:exists;

	{ kind => 'response', id => %msg<id>, result => %msg<result>, raw => $line, message => %msg };
}

#| Give a result the shape a 2026-07-28 result has. A legacy server sends no
#| C<resultType> at all, and a modern one may omit it; either way the result is
#| complete, because a server that wanted something from us would have said so.
#| Anything that is not an object at all (JSON C<null>, a bare string) becomes
#| an empty complete result rather than an error: the response arrived, it just
#| carries nothing to read.
sub normalize-result($result --> Hash) is export {
	return { resultType => RESULT-TYPE-COMPLETE } unless $result ~~ Associative;
	my %out = $result.Hash;
	%out<resultType> = RESULT-TYPE-COMPLETE
		unless (%out<resultType>:exists) && %out<resultType> ~~ Str:D && %out<resultType>.chars;
	%out;
}

#| True when an error object carries one of the 2026-07-28-only codes. Both era
#| probes lean on this: a server that answers with -32022 has told us it is
#| modern even while refusing the request.
sub is-modern-error($error --> Bool) is export {
	return False unless $error ~~ Associative;
	my $code = $error<code>;
	return False unless $code ~~ Real:D;
	MODERN-ERROR-CODES.grep({ $_ == $code }).elems > 0;
}

#| Write the polite refusal to a server-initiated input request — the answer
#| the multi round-trip loop sends when the caller wired no hook for that kind
#| of input, or when their hook threw.
#|
#| Returns the I<value> half of one C<inputResponses> entry, not an envelope
#| around it. C<InputResponses> is a map whose keys are the server-assigned
#| keys from the C<inputRequests> map it is answering and whose values are bare
#| client results — C<ElicitResult>, C<ListRootsResult> or
#| C<CreateMessageResult>. There is no id member and no error member anywhere
#| in that structure, so a refusal has to be expressible as a result or not
#| sent at all:
#|
#| =item C<elicitation/create> — C<< { action => 'decline' } >>. C<ElicitResult>
#|       defines C<action> as C<accept|decline|cancel>, so declining is a
#|       first-class answer.
#| =item C<roots/list> — C<< { roots => [] } >>. An empty root list is a valid
#|       C<ListRootsResult> and it is the true one: we expose nothing.
#| =item C<sampling/createMessage>, and any method we do not recognise — an
#|       B<undefined Hash>, meaning "leave this key out of C<inputResponses>
#|       altogether". C<CreateMessageResult> requires a model, a role and
#|       content, so it cannot say "no"; inventing one would be a lie about
#|       what an LLM produced. Omission is the spec's own path: a server that
#|       does not get an answer it needs SHOULD ask again, and the client's
#|       round budget bounds how often it may.
#|
#| Note that a server MUST NOT ask for input the client did not declare a
#| capability for, so a well-behaved server never reaches the omission branch:
#| MCP::Client only declares C<sampling> when an C<on-sample> hook is wired.
#|
#| Shapes verified 2026-08-08 against
#| L<https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>
#| and the schema at
#| L<https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts>.
sub decline-input-response($request --> Hash) is export {
	my %req = $request ~~ Associative ?? $request.Hash !! {};
	my $method = %req<method> ~~ Str:D ?? %req<method> !! '';

	do given $method {
		when 'elicitation/create' { %( action => 'decline' ) }
		when 'roots/list'         { %( roots => [] ) }
		default                   { Hash }
	}
}
