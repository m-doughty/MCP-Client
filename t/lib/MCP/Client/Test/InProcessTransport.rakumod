=begin pod

=head1 NAME

MCP::Client::Test::InProcessTransport - drive a live MCP::Server with no wire

=head1 DESCRIPTION

A transport whose "server" is an C<MCP::Server> object in this very process.
Requests are handed to C<handle-modern-request>, the seam
L<MCP::Server::HTTP> uses, and its response is turned back into the promise
C<MCP::Client> expects — JSON-RPC error to C<X::MCP::Client::Protocol>, result
through C<normalize-result>, notifications to C<&on-notification>.

That makes it the cheapest possible contract test: real server code, real
result envelopes, real cache metadata, real error codes, and not one subprocess,
socket or serialisation step in the way. What it cannot test is the wire itself
— framing, line splitting, a server that dies — which is what the spawned
fixture in C<t/08> and C<t/09> is for.

=head2 Modern era only

C<handle-modern-request> B<forces> the modern era (see its documentation in
C<MCP::Server>): it does not sniff the message, it declares it. So a legacy-era
request sent through this transport is answered the way a 2026-07-28 server
answers one, which is to say it fails cleanly:

=item C<initialize>, C<ping> and C<logging/setLevel> are the methods the modern
      era removed, so they come back as C<-32601 METHOD_NOT_FOUND> and reach the
      caller as an C<X::MCP::Client::Protocol> with that code. C<MCP::Client>
      reads C<-32601> on C<initialize> as "this is not a legacy server" and on
      C<ping> as "this server has no ping", both of which are true.
=item Any other method sent without the modern C<params._meta> block fails the
      version gate with C<-32022 UNSUPPORTED_PROTOCOL_VERSION>, again as an
      C<X::MCP::Client::Protocol>.

Nothing hangs and nothing throws an untyped exception, but a client that is
pushed down the legacy path against this transport will fail its handshake. Use
the spawned fixture for legacy coverage.

=head1 EXAMPLES

=begin code :lang<raku>
use MCP::Server;
use MCP::Client;
use MCP::Client::Test::InProcessTransport;
use MCP::Client::Test::TestKit;

my $server = MCP::Server.new(:name<contract>, :version<1.0.0>);
$server.plug(MCP::Client::Test::TestKit.new);

my $wire = MCP::Client::Test::InProcessTransport.new(server => $server);
my $client = MCP::Client.new(transport => $wire, log-level => 'info');

is $client.era, 'modern';
is $client.call-tool('echo', { text => 'hi' })<content>[0]<text>, 'hi';
is $wire.requests-for('tools/call').elems, 1;
=end code

=end pod

use MCP::Server::Protocol;

use MCP::Client::Exceptions;
use MCP::Client::Protocol;
use MCP::Client::Transport;

unit class MCP::Client::Test::InProcessTransport does MCP::Client::Transport;

#| The server under test. Anything with C<handle-modern-request> will do.
has $.server is required;

#| Requests are dispatched on a thread of their own so several may be in flight
#| at once, exactly as they can be down a real pipe. Set C<:!concurrent> to
#| dispatch on the calling thread instead, which makes a failure's backtrace
#| point at the test that caused it.
has Bool:D $.concurrent = True;

#| Every request the client sent, in order.
has @.requests;

#| Every notification the client sent, in order.
has @.notifications;

#| How many times C<close> was called.
has Int $.closes = 0;

has Lock $!lock .= new;
has Bool $!open = True;

#| The requests for one method, in order.
method requests-for(Str:D $method --> List:D) {
	$!lock.protect: { @!requests.grep({ ($_<method> // '') eq $method }).List };
}

#| How many requests the client sent for one method — the count that proves a
#| cache hit never reached the server.
method count-for(Str:D $method --> Int:D) {
	self.requests-for($method).elems;
}

#| The methods of every request sent, in order.
method sent-methods(--> List:D) {
	$!lock.protect: { @!requests.map({ $_<method> // '' }).List };
}

method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
	$!lock.protect: { @!requests.push(%msg) };

	return Promise.broken(X::MCP::Client::TransportClosed.new(
		detail => 'InProcessTransport was closed',
	)) unless $!lock.protect: { $!open };

	with $cancelled {
		return Promise.broken(X::MCP::Client::Cancelled.new(
			id => %msg<id>, method => (%msg<method> ~~ Str:D ?? %msg<method> !! Str),
		)) if .status ~~ Kept;
	}

	my $promise = Promise.new;
	my $vow = $promise.vow;
	my $settled = Lock.new;
	my Bool $done = False;

	# The vow is claimed under a lock because three things race for it: the
	# handler finishing, the caller cancelling, and the budget running out.
	my &settle = -> &act {
		my Bool $mine = False;
		$settled.protect: { $mine = !$done; $done = True };
		act() if $mine;
	};

	my &work = {
		CATCH {
			default {
				# A server that throws rather than returning an error response is
				# a server bug, but a transport that lets it escape onto a
				# scheduler thread is a worse one.
				my $why = .message.lines.head;
				settle({ $vow.break(X::MCP::Client::Protocol.new(
					detail => "the in-process server threw: $why",
				)) });
			}
		}

		my %response = $!server.handle-modern-request(
			%msg,
			notify => -> %note {
				# Never let a subscriber take the server's thread down with it.
				CATCH { default { } }
				&on-notification(%note) if &on-notification;
			},
			|($cancelled.defined ?? (:$cancelled) !! ()),
		);

		settle({
			if %response<error> ~~ Associative {
				my %error = %response<error>.Hash;
				$vow.break(X::MCP::Client::Protocol.new(
					detail => (%error<message> ~~ Str:D ?? %error<message> !! 'server error'),
					code   => (%error<code> ~~ Real:D ?? %error<code>.Int !! Int),
					data   => %error<data>,
				));
			}
			else {
				$vow.keep(normalize-result(%response<result>));
			}
		});
	};

	with $cancelled {
		.then(-> $c {
			$c.cause if $c.status ~~ Broken;
			settle({ $vow.break(X::MCP::Client::Cancelled.new(
				id => %msg<id>, method => (%msg<method> ~~ Str:D ?? %msg<method> !! Str),
			)) });
		});
	}

	if $timeout ~~ Real:D && $timeout > 0 {
		Promise.in($timeout).then({
			settle({ $vow.break(X::MCP::Client::Timeout.new(
				seconds => $timeout.Real,
				method  => (%msg<method> ~~ Str:D ?? %msg<method> !! Str),
				id      => %msg<id>,
			)) });
		});
	}

	$!concurrent ?? (start work()) !! work();
	$promise;
}

method notify(%msg --> Nil) {
	$!lock.protect: { @!notifications.push(%msg) };
	return unless $!lock.protect: { $!open };

	# Dispatched for its side effects: the seam answers an id-less message with
	# an empty hash, and there is nothing to correlate.
	CATCH { default { } }
	$!server.handle-modern-request(%msg);
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
