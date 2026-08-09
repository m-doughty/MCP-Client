=begin pod

=head1 NAME

MCP::Client::Transport - the seam between MCP::Client and a wire

=head1 DESCRIPTION

C<MCP::Client> knows the protocol; a transport knows how to get a message to a
server and an answer back. Everything era-specific, everything about caching,
multi round-trips, capabilities and typed results lives in the client. A
transport does four things and nothing else: send a request and promise an
answer, send a notification, close, and say whether it is still usable.

That division is what makes the client testable. A scripted double that does
this role is indistinguishable from a spawned subprocess as far as
C<MCP::Client> is concerned, so the era probe, the multi round-trip loop and
the whole typed API can be exercised without a server anywhere in sight.

=head2 The contract

Doing this role means signing up to more than four method names. The parts a
transport must get right, and that C<MCP::Client> relies on absolutely:

=item B<The client owns the ids.> Every message handed to C<request> already
      carries its JSON-RPC C<id>; a transport correlates on that id and must
      never renumber. The multi round-trip loop depends on it — a retry is a
      new id by protocol requirement, and the client is the only party that
      knows a retry is happening.
=item B<The promise carries the result, not the response.> Keep it with the
      C<result> member, run through
      C<MCP::Client::Protocol::normalize-result> so a legacy result arrives
      with the C<resultType> a modern one would have had. Never keep it with
      the whole JSON-RPC envelope.
=item B<A JSON-RPC error breaks the promise.> Break it with an
      C<X::MCP::Client::Protocol> carrying the wire C<code> and verbatim
      C<data>; the era probe reads both. Break with
      C<X::MCP::Client::Timeout> when the budget runs out, with
      C<X::MCP::Client::ServerGone> when the peer dies, with
      C<X::MCP::Client::TransportClosed> after C<close>, and with
      C<X::MCP::Client::Cancelled> when C<$cancelled> is kept. The probe
      treats those four as fatal and everything else as evidence about the
      server's era, so a transport that invents its own exception types will
      have them read as "this server is ancient".
=item B<Notifications go to C<&on-notification>, never to the promise.> It is
      called with the parsed notification hash (C<method>, C<params>) and must
      never be allowed to break the read loop: wrap the call.
=item B<Signatures match exactly.> An implementation whose C<request> differs
      by so much as a trait becomes a second multi candidate rather than an
      override, and the role's stub — which dies — stays reachable. Copy the
      signatures below verbatim.

=head1 EXAMPLES

The whole role, as a null transport that answers everything with an empty
complete result:

=begin code :lang<raku>
use MCP::Client::Transport;
use MCP::Client::Protocol;
use MCP::Client::Exceptions;

class NullTransport does MCP::Client::Transport {
	has Bool $!open = True;

	method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
		return Promise.broken(X::MCP::Client::TransportClosed.new) unless $!open;
		Promise.kept(normalize-result({}));
	}
	method notify(%msg --> Nil) { }
	method close(--> Nil) { $!open = False }
	method alive(--> Bool) { $!open }
}

my $client = MCP::Client.new(transport => NullTransport.new);
=end code

A sketch of the real thing, showing where each part of the contract lands:

=begin code :lang<raku>
method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
	my $answer = $!correlator.register(
		%msg<id>, method => %msg<method>, timeout => ($timeout // $!default-timeout),
	);
	$!lock.protect: { %!listeners{%msg<id>} = &on-notification if &on-notification };
	$!proc.print(format-message(%msg));

	with $cancelled {
		.then({ $!correlator.cancel(%msg<id>) });
	}
	$answer;
}

# ... on the read loop, for every inbound line:
my %in = parse-inbound($line);
if %in<kind> eq 'response' && (%in<error>:exists) {
	$!correlator.reject(%in<id>, X::MCP::Client::Protocol.new(
		detail => %in<error><message> // 'server error',
		code   => %in<error><code>,
		data   => %in<error><data>,
	));
}
elsif %in<kind> eq 'response' {
	$!correlator.resolve(%in<id>, normalize-result(%in<result>));
}
elsif %in<kind> eq 'notification' {
	# Never let a subscriber take the read loop down with it.
	try $_(%in) for self!listeners;
}
=end code

=end pod

unit role MCP::Client::Transport;

#| Send one request and promise its answer.
#|
#| %msg is a complete JSON-RPC request object, id and all, exactly as
#| C<MCP::Client::Protocol::build-request> produced it. The returned Promise is
#| kept with the normalised C<result> hash, or broken with an
#| C<X::MCP::Client> subclass (see the contract above). It must be a Promise
#| that is eventually settled: an implementation that can neither answer nor
#| fail is a hung client.
#|
#| C<&on-notification> receives every notification the server emits while this
#| request is outstanding — for stdio, where one pipe carries everything, that
#| may include notifications belonging to other work; for HTTP it is exactly
#| the notifications on this request's stream.
#|
#| C<$cancelled>, when supplied and kept, abandons the request: the promise
#| breaks with C<X::MCP::Client::Cancelled> and any late answer is dropped.
#|
#| C<$timeout> is in seconds; C<0> or a negative number means "no timeout", and
#| an undefined value means "use the transport's own default".
method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) { ... }

#| Send one notification. Fire and forget: there is no answer to a JSON-RPC
#| notification, and a transport that cannot deliver one must not throw at the
#| caller — the client uses this for C<notifications/initialized>, where the
#| failure will surface on the next real request anyway.
method notify(%msg --> Nil) { ... }

#| Shut the connection down and fail everything still outstanding. Must be
#| idempotent: C<MCP::Client.close> is allowed to be called twice, and a
#| transport whose peer has already died will be closed again on the way out.
method close(--> Nil) { ... }

#| False once the connection is gone — closed deliberately, or the child
#| process exited, or the HTTP endpoint stopped answering. Advisory only:
#| C<alive> being True is never a promise that the next request will succeed,
#| so the client checks results rather than gating on this.
method alive(--> Bool) { ... }
