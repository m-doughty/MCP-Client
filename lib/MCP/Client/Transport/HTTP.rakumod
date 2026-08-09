=begin pod

=head1 NAME

MCP::Client::Transport::HTTP - Streamable HTTP transport for MCP::Client

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client;

my $mcp = MCP::Client.connect-http(
	url     => 'http://127.0.0.1:8080/mcp',
	headers => { Authorization => 'Bearer s3cret' },
);

say $mcp.list-tools.map(*<name>).join(', ');
say $mcp.call-tool('greet', { name => 'Ada' })<content>[0]<text>;
$mcp.close;
=end code

=head1 DESCRIPTION

The 2026-07-28 Streamable HTTP transport, and only that one: a single POST
endpoint, no sessions, no C<GET> stream, no resumability, and every request
self-describing through its C<params._meta>. The legacy HTTP session transport
(C<Mcp-Session-Id>, C<Last-Event-ID>, server-initiated requests on a stream) is
deliberately not implemented — see L<#Limitations>.

C<MCP::Client> loads this module on demand, so a stdio client never pays for
Cro's load time. You rarely construct it yourself; C<connect-http> does it for
you. When you do, every attribute below is available.

=head2 What one request looks like

Each JSON-RPC message is its own C<POST>. The body is the message; a handful of
its fields are B<mirrored into headers> so that load balancers and gateways can
route without parsing JSON:

=begin code
POST /mcp HTTP/1.1
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2026-07-28
Mcp-Method: tools/call
Mcp-Name: execute_sql
Mcp-Param-Region: us-west1
=end code

C<MCP-Protocol-Version> is taken from the outbound body's C<_meta>, never
guessed, because a server B<MUST> reject the request when the two disagree.
C<Mcp-Name> carries C<params.name> for C<tools/call> and C<prompts/get>, and
C<params.uri> for C<resources/read>. C<Mcp-Param-*> is the C<x-mcp-header>
feature described below.

The answer is one of four things:

=item B<200 C<application/json>> — the body is the JSON-RPC response.
=item B<200 C<text/event-stream>> — notifications for this request arrive as
      SSE events, then the response, which ends the stream. Notifications go to
      C<&on-notification>; the response settles the promise.
=item B<202> — the acknowledgement of a notification (C<notify>). Seeing one in
      answer to a request is a protocol error.
=item B<400 / 404 / anything else> — the body is parsed for a JSON-RPC error and
      surfaced as an C<X::MCP::Client::Protocol> carrying the wire C<code> and
      C<data>. That matters for the era probe: a modern server answers an
      unknown version with C<400> and C<-32022>, which is evidence about the
      server rather than a dead end.

=head2 x-mcp-header

A server may ask for a tool argument to be copied into a header by putting an
C<x-mcp-header> annotation on that argument's schema. Supporting it is a client
B<MUST>, so this transport does — without C<MCP::Client> having to know:
C<tools/list> responses pass through here on their way up, and their
annotations are captured as they go.

Annotations are validated on the way through, and a tool whose annotations
break any of the rules is B<excluded> from the C<tools/list> result handed to
the caller (with a warning through C<&.on-warn>), so one malformed tool cannot
take the rest of the catalog with it.

=begin code :lang<raku>
# What the transport does for you when the server publishes this:
{
	name        => 'execute_sql',
	inputSchema => {
		type       => 'object',
		properties => {
			region => { type => 'string', 'x-mcp-header' => 'Region' },
			query  => { type => 'string' },
		},
	},
}

# ... a later call-tool('execute_sql', { region => 'us-west1', ... }) sends
# Mcp-Param-Region: us-west1
=end code

Values that cannot travel as a plain ASCII header value are carried in the
base64 sentinel format, which the server decodes before comparing them to the
body:

=begin code :lang<raku>
use MCP::Client::Transport::HTTP;

say header-encode('us-west1');      # us-west1
say header-encode('Hello, 世界');    # =?base64?SGVsbG8sIOS4lueVjA==?=
say header-encode(' padded ');      # =?base64?IHBhZGRlZCA=?=
say header-encode('=?base64?x?=');  # =?base64?PT9iYXNlNjQ/eD89?=
=end code

=head2 Cancellation

Closing the response stream is the only cancellation signal this protocol has,
so that is exactly what C<:$cancelled> does: the response is cancelled, the
connection goes away, the server sees the hang-up, and the promise breaks with
C<X::MCP::Client::Cancelled>.

=begin code :lang<raku>
my $stop = Promise.new;
my $answer = $mcp.call-tool-async('slow', {}, cancelled => $stop);
$stop.keep(True);           # the server is told by the disconnect itself
=end code

=head2 Testing seams

The pieces that decide what goes on the wire are plain subs, exported so they
can be tested (and reused) without a server:

=item C<header-encode($value)> — the base64 sentinel rule.
=item C<request-headers(%msg, :%annotations, :$protocol-version)> — every header
      one message implies, as a list of C<Pair>s.
=item C<tool-header-annotations(%tool)> — C<< { valid, reason, headers } >> for one
      tool definition.
=item C<response-kind($status, $content-type)> — C<sse|json|accepted|error>.
=item C<error-for-status($status, $body)> — the C<X::MCP::Client::Protocol> an
      unsuccessful response deserves, coded when the body says so.

=head2 Limitations

=item Modern era only. There is no C<initialize> handshake over HTTP, and a
      server that only speaks C<2025-11-25> over HTTP cannot be talked to.
=item No C<subscriptions/listen>, so no long-lived notification stream. Cache
      freshness comes from C<ttlMs> alone.
=item No OAuth. Static credentials go in C<%.headers>.
=item HTTP/1.1 by default, on purpose (see C<$.http-version>).

=end pod

use Cro::HTTP::Client;
use JSON::Fast;
use MIME::Base64;

use MCP::Server::Protocol;

use MCP::Client::Exceptions;
use MCP::Client::Protocol;
use MCP::Client::SSE;
use MCP::Client::Transport;

unit class MCP::Client::Transport::HTTP does MCP::Client::Transport;

# === Wire vocabulary ===
#
# Everything in this section was verified 2026-08-08 against
# https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
# and cross-checked against the server side in MCP::Server::HTTP::Validation.

#| Which params field a method's Mcp-Name header comes from. "These headers are
#| REQUIRED for compliance" for exactly these three methods; the header is
#| ignored (not forbidden) elsewhere, so we send it only where it means
#| something.
my constant %NAME-FIELD-FOR-METHOD = Map.new(
	'tools/call'     => 'name',
	'prompts/get'    => 'name',
	'resources/read' => 'uri',
);

#| The JSON Schema types an x-mcp-header annotation may sit on: "MUST only be
#| applied to parameters with primitive types (integer, string, boolean).
#| Parameters with type `number` are not permitted."
my constant PRIMITIVE-TYPES = set(<string integer boolean>);

#| tchar, RFC 9110 section 5.1, minus the alphanumerics handled by range.
my constant TCHAR-SYMBOLS = set('!', '#', '$', '%', '&', "'", '*', '+', '-', '.', '^', '_', '`', '|', '~');

# The `=?base64?...?=` sentinel, spelled exactly as the server's decoder spells
# it (MCP::Server::HTTP::Validation): the markers are case-sensitive and
# lowercase-only, and prefix and suffix may not overlap.
my regex sentinel { ^ '=?base64?' .* '?=' $ }

#| Header names this transport derives from the message itself. A caller-supplied
#| copy would arrive as a second header, which RFC 9110 says to join with a comma
#| — and a comma-joined Mcp-Method matches no method at all.
my constant RESERVED-HEADERS = set(<
	mcp-protocol-version mcp-method mcp-name accept content-type
>);

# === Attributes ===

#| The MCP endpoint, e.g. C<http://127.0.0.1:8080/mcp>.
has Str:D $.url is required;

#| Extra headers sent with every request — an C<Authorization>, a tenant id, a
#| trace header. Names the transport derives itself are refused at construction
#| rather than silently duplicated on the wire.
has %.headers;

#| C<'1.1'> (the default), C<'2'>, or C<< <1.1 2> >> to let ALPN decide.
#|
#| The default is a pin, not an accident. Cro negotiates the HTTP version over
#| ALPN for HTTPS, which means it can pick HTTP/2 against a gateway that
#| advertises it, and Cro's HTTP/2 client has been observed to hang waiting for
#| response headers against some upstream-routed providers — the same bug
#| L<LLM::Chat> pins 1.1 for. An MCP call that hangs until the request budget
#| expires is indistinguishable from a broken server, so the safe version is the
#| default and the fast one is opt-in.
has $.http-version = '1.1';

#| Reuse connections between requests. False by default: cancelling a request
#| means tearing its connection down, and doing that to a pooled connection is a
#| good way to take an unrelated request with it.
has Bool:D $.persistent = False;

#| Seconds a request may take when the caller names no budget of its own. C<0>
#| or less means "no budget".
has Real:D $.default-timeout = 60;

#| Seconds to get a TCP (and TLS) connection up. Separate from the request
#| budget: a refused connection should fail now, not in a minute.
has Real:D $.connect-timeout = 30;

#| The version stamped on C<MCP-Protocol-Version> when the outbound body carries
#| no C<_meta> version to copy. The header value B<MUST> match the body, so this
#| is only ever a fallback for messages built outside the modern era.
has Str:D $.protocol-version = MODERN-PROTOCOL-VERSION;

#| Called with a one-line diagnostic when the transport papers over something:
#| a tool excluded for a bad annotation, a notification subscriber that threw, a
#| stray event on a response stream. Defaults to writing to C<$*ERR>.
has &.on-warn = -> Str:D $message { note "[MCP::Client::Transport::HTTP] $message" };

has Cro::HTTP::Client $!client;
has Lock $!lock .= new;
has Bool $!open = True;
has Int  $!next-token = 0;

# Tool name => (header name => the property path its value lives at), captured
# from every tools/list response that passes through.
has %!annotations;

# Token => a closure that fails the exchange and tears its stream down, so
# close() can settle everything still in flight.
has %!in-flight;

submethod TWEAK() {
	die X::MCP::Client.new(detail => 'the HTTP transport needs a non-empty url')
		unless $!url.chars;
	die X::MCP::Client.new(
		detail => "unusable MCP endpoint '$!url': expected an http:// or https:// URL",
	) unless $!url.lc.starts-with('http://') || $!url.lc.starts-with('https://');

	die X::MCP::Client.new(detail => 'connect-timeout must be greater than zero')
		unless $!connect-timeout > 0;

	unless $!http-version eqv '1.1' || $!http-version eqv '2' || $!http-version eqv <1.1 2> {
		die X::MCP::Client.new(
			detail => "unsupported http-version '{$!http-version.raku}' "
				~ "(expected '1.1', '2', or <1.1 2>)",
		);
	}

	for %!headers.keys.sort -> $name {
		die X::MCP::Client.new(
			detail => "the '$name' header is derived from each message and cannot be "
				~ 'set on the transport',
		) if RESERVED-HEADERS{$name.lc} || $name.lc.starts-with('mcp-param-');
	}

	$!client = Cro::HTTP::Client.new(http => $!http-version, persistent => $!persistent);
}

# === One request in flight ===
#
# A request has three parties racing for it: the response arriving, the budget
# running out, and the caller cancelling. Exactly one of them settles the
# promise, and whichever it is has to be able to tear the response stream down —
# including when the stream has not turned up yet, which is why `arm` cancels
# immediately rather than storing a teardown nobody will ever call.
my class Exchange {
	has Promise:D $.outcome .= new;
	has Str       $.method;
	has           $.id;
	has           &.forget;

	has Lock $!lock .= new;
	has Bool $!settled = False;
	has      &!abort;

	#| Settle the outcome, once. An Exception breaks it, anything else keeps it.
	#| True when this call was the one that settled it.
	method settle($value --> Bool) {
		my Bool $first = $!lock.protect: {
			my $was = $!settled;
			$!settled = True;
			!$was;
		};

		if $first {
			with &!forget { try &!forget() }
			$value ~~ Exception ?? $!outcome.break($value) !! $!outcome.keep($value);
		}
		$first;
	}

	#| Hand over the means to tear the response stream down. An exchange that is
	#| already settled uses it at once instead of storing it: the answer stopped
	#| being wanted while it was still on its way.
	method arm(&abort --> Nil) {
		my Bool $too-late = $!lock.protect: {
			$!settled ?? True !! do { &!abort = &abort; False };
		};
		try &abort() if $too-late;
		Nil;
	}

	method abandon(--> Nil) {
		my &teardown = $!lock.protect: {
			my &held = &!abort;
			&!abort = Callable;
			&held;
		};
		with &teardown { try &teardown() }
		Nil;
	}

	method settled(--> Bool) { $!lock.protect: { $!settled } }

	#| Break the promise and hang up, in that order.
	method fail(Exception:D $error --> Nil) {
		self.settle($error);
		self.abandon;
		Nil;
	}
}

# === The transport role ===

method request(%msg, :&on-notification, Promise :$cancelled, :$timeout --> Promise) {
	my Str $method = %msg<method> ~~ Str:D ?? %msg<method> !! Str;
	my $id = %msg<id>;

	my Int $token = $!lock.protect: { ++$!next-token };
	my $exchange = Exchange.new(
		:$method, :$id,
		forget => sub { $!lock.protect: { %!in-flight{$token}:delete } },
	);

	my Bool $registered = $!lock.protect: {
		if $!open {
			%!in-flight{$token} = sub {
				$exchange.fail(X::MCP::Client::TransportClosed.new(
					detail => 'the HTTP transport was closed with this request in flight',
				));
			};
			True;
		}
		else {
			False;
		}
	};

	unless $registered {
		$exchange.settle(X::MCP::Client::TransportClosed.new(
			detail => 'the HTTP transport has been closed',
		));
		return $exchange.outcome;
	}

	my Real $budget = self!budget($timeout);

	if $budget > 0 {
		Promise.in($budget).then(sub ($) {
			$exchange.fail(X::MCP::Client::Timeout.new(seconds => $budget, :$method, :$id))
				unless $exchange.settled;
		});
	}

	with $cancelled {
		$cancelled.then(sub ($promise) {
			if $promise.status === Kept && !$exchange.settled {
				$exchange.fail(X::MCP::Client::Cancelled.new(:$method, :$id));
			}
		});
	}

	start {
		CATCH {
			default { $exchange.fail(self!wire-failure($_, $method, $id, $budget)) }
		}
		self!exchange(%msg, $exchange, &on-notification, $budget);
	}

	$exchange.outcome;
}

method notify(%msg --> Nil) {
	# A notification that cannot be delivered must not throw at the caller: the
	# client uses this where the failure will surface on the next real request.
	CATCH {
		default {
			self!warn("could not send notification '{%msg<method> // '?'}': "
				~ .message.lines.head);
		}
	}

	return unless self.alive;

	my $posted = self!post(%msg, self!budget(Real));
	$posted.then(sub ($promise) {
		if $promise.status === Broken {
			my $cause = $promise.cause;
			my $what = $cause ~~ X::Cro::HTTP::Error
				?? 'HTTP ' ~ $cause.response.status
				!! $cause.message.lines.head;
			self!warn("the server refused notification '{%msg<method> // '?'}': $what");
		}
		elsif $promise.result.status != 202 {
			self!warn("the server answered notification '{%msg<method> // '?'}' with "
				~ $promise.result.status ~ ' rather than 202');
		}
	});

	Nil;
}

method close(--> Nil) {
	my @closers;
	$!lock.protect: {
		$!open = False;
		@closers = %!in-flight.values;
		%!in-flight = ();
		%!annotations = ();
	}

	# Outside the lock: each closer settles an exchange, and settling reaches
	# back in here to forget it.
	for @closers -> &closer { try &closer() }
	Nil;
}

method alive(--> Bool) {
	$!lock.protect: { $!open }
}

# === Tool annotations ===

#| The C<x-mcp-header> annotations this transport has captured, tool name =>
#| (header name => the property path its value lives at). Diagnostic: the
#| capture happens by itself, on every C<tools/list> response.
method tool-annotations(--> Hash:D) {
	$!lock.protect: { %!annotations.Hash };
}

#| Record the annotations a C<tools/list> result carries and hand the result
#| back with every tool the specification says we must reject removed.
#|
#| "Clients using the Streamable HTTP transport MUST reject tool definitions
#| where any C<x-mcp-header> value violates these constraints. Rejection means
#| the client MUST exclude the invalid tool from the result of C<tools/list>.
#| Clients SHOULD log a warning when rejecting a tool definition, including the
#| tool name and the reason for rejection."
#|
#| Called for you on the way past; public because a caller embedding this
#| transport directly may want to prime it, and because it is the seam the
#| tests drive.
method capture-tool-list(%result --> Hash:D) {
	my %out = %result.Hash;
	return %out unless %out<tools> ~~ Positional;

	my @kept;
	my %annotations;

	for %out<tools>.list -> $tool {
		# Not a tool definition at all: not ours to judge, and the client's own
		# shape checks will have a better complaint than we would.
		unless $tool ~~ Associative {
			@kept.push($tool);
			next;
		}

		my %tool = $tool.Hash;
		my Str $name = %tool<name> ~~ Str:D ?? %tool<name> !! '';
		my %check = tool-header-annotations(%tool);

		unless %check<valid> {
			self!warn("excluding tool '{$name.chars ?? $name !! '(unnamed)'}' from "
				~ 'tools/list: ' ~ %check<reason>);
			next;
		}

		%annotations{$name} = %check<headers> if $name.chars && %check<headers>.elems;
		@kept.push($tool);
	}

	$!lock.protect: { %!annotations = %annotations };
	%out<tools> = @kept;
	%out;
}

# === Doing one exchange ===

method !exchange(%msg, Exchange:D $exchange, &on-notification, Real:D $budget --> Nil) {
	my $response = await response-of(self!post(%msg, $budget));

	# From here on the response body is a live stream, and cancelling it is how
	# this protocol says "stop".
	$exchange.arm(sub { try $response.cancel });
	return if $exchange.settled;

	my $kind = response-kind($response.status, $response.header('Content-Type'));

	given $kind {
		when 'sse'  { self!consume-stream(%msg, $response, $exchange, &on-notification) }
		when 'json' { self!consume-json(%msg, $response, $exchange) }
		when 'accepted' {
			$exchange.fail(X::MCP::Client::Protocol.new(
				detail => "the server acknowledged '{%msg<method> // '?'}' with 202 rather "
					~ 'than answering it, which JSON-RPC only allows for a notification',
			));
		}
		default {
			my $body = body-text($response);
			$exchange.settle(error-for-status($response.status, $body));
		}
	}
	Nil;
}

method !post(%msg, Real:D $budget --> Promise:D) {
	$!client.post(
		$!url,
		content-type => 'application/json',
		body         => to-json(%msg, :!pretty),
		headers      => self!headers-for(%msg),
		# The response headers do not arrive until the server has decided
		# between JSON and a stream, which for a slow tool call is only when the
		# handler speaks or finishes -- so the headers phase gets the whole
		# request budget rather than Cro's 60s default. The body phase is left
		# unbounded: our own budget covers it, and a stream that keeps sending
		# keepalives is healthy, not stuck.
		timeout      => %(
			connection => $!connect-timeout,
			headers    => ($budget > 0 ?? $budget !! Inf),
			body       => Inf,
		),
	);
}

method !consume-json(%msg, $response, Exchange:D $exchange --> Nil) {
	my %in = parse-inbound(body-text($response));

	if %in<kind> eq 'response' {
		self!check-id(%in<id>, %msg<id>);
		%in<error>:exists
			?? $exchange.settle(protocol-error(%in<error>))
			!! $exchange.settle(self!post-process(%msg, normalize-result(%in<result>)));
	}
	else {
		$exchange.settle(X::MCP::Client::Protocol.new(
			detail => 'the server answered with a body that is not a JSON-RPC response ('
				~ (%in<reason> // %in<kind>) ~ ')',
		));
	}
	Nil;
}

method !consume-stream(%msg, $response, Exchange:D $exchange, &on-notification --> Nil) {
	my $sse = MCP::Client::SSE.new;
	my $answered = Promise.new;
	my $finished = Promise.new;
	my $failure;

	# Tapped before a single byte is fed: the events supply is live, and what it
	# emits while nobody is listening is gone.
	$sse.events.tap: sub (%event) {
		self!dispatch-event(%event, %msg, $exchange, &on-notification, $answered);
	};

	my $tap = $response.body-byte-stream.tap(
		sub ($bytes) { $sse.feed($bytes) },
		done => sub {
			# :flush, because the last event of an HTTP response body routinely
			# arrives without its trailing blank line -- and for MCP that last
			# event is the response the caller is waiting for.
			$sse.close(:flush);
			try $finished.keep(True);
		},
		quit => sub ($error) {
			$failure = $error;
			$sse.quit($error ~~ Exception ?? $error !! X::AdHoc.new(payload => $error));
			try $finished.keep(True);
		},
	);

	# Whichever comes first: the stream ending, or the response event that ends
	# the request. The specification says the response SHOULD terminate the
	# stream, and a server that keeps it open anyway has nothing left to say
	# that this request can use.
	await Promise.anyof($finished, $answered);
	$tap.close;
	$sse.close(:flush);

	unless $exchange.settled {
		$exchange.settle(
			$failure.defined
				?? X::MCP::Client::ServerGone.new(
					command     => $!url,
					stderr-tail => first-line($failure),
				)
				!! X::MCP::Client::Protocol.new(
					detail => 'the event stream ended without a JSON-RPC response',
				)
		);
	}
	Nil;
}

method !dispatch-event(%event, %msg, Exchange:D $exchange, &on-notification, Promise:D $answered --> Nil) {
	my $data = %event<data>;
	return without $data;

	my %in = parse-inbound($data);

	given %in<kind> {
		when 'response' {
			self!check-id(%in<id>, %msg<id>);
			%in<error>:exists
				?? $exchange.settle(protocol-error(%in<error>))
				!! $exchange.settle(self!post-process(%msg, normalize-result(%in<result>)));
			try $answered.keep(True);
		}
		when 'notification' {
			# A subscriber that throws must not be able to take the stream, and
			# with it the request, down.
			with &on-notification {
				my $delivered = try { &on-notification(%in); True };
				self!warn("a notification subscriber threw on '{%in<method> // '?'}'")
					unless $delivered;
			}
		}
		when 'request' {
			# 2026-07-28: "The server MUST NOT send independent JSON-RPC
			# requests on this stream." Sampling and friends arrive as
			# inputRequests inside a result instead.
			self!warn("dropped a server request for '{%in<method> // '?'}' on a response "
				~ 'stream, where 2026-07-28 forbids one');
		}
		default {
			self!warn('dropped an unreadable event on the response stream: '
				~ (%in<reason> // 'unknown'));
		}
	}
	Nil;
}

# tools/list is the one response this transport reads rather than passes
# through: its x-mcp-header annotations are what makes the next tools/call
# well-formed, and capturing them here is what keeps MCP::Client from having to
# know that HTTP has opinions about tool schemas.
method !post-process(%msg, %result --> Hash:D) {
	return %result unless (%msg<method> // '') eq 'tools/list';
	self.capture-tool-list(%result);
}

# === Headers ===

method !headers-for(%msg --> List:D) {
	my %annotations;

	if (%msg<method> // '') eq 'tools/call' {
		my $params = %msg<params>;
		my $name = $params ~~ Associative ?? $params<name> !! Any;
		%annotations = $!lock.protect({ (%!annotations{$name} // {}).Hash })
			if $name ~~ Str:D;
	}

	(
		|%!headers.sort(*.key).map({ .key => .value.Str }),
		|request-headers(%msg, :%annotations, protocol-version => $!protocol-version),
	).List;
}

# HTTP has exactly one request per response, so a mismatched id cannot be
# somebody else's answer -- it is the only answer we are going to get. Saying so
# and using it beats hanging until the budget expires.
method !check-id($got, $sent --> Nil) {
	return unless $got.defined && $sent.defined;
	return if $got.Str eq $sent.Str;
	self!warn("the server answered id '{$got.Str}' to request id '{$sent.Str}'");
	Nil;
}

# === Failure mapping ===

method !wire-failure($error, Str $method, $id, Real:D $budget --> Exception:D) {
	return $error if $error ~~ X::MCP::Client;

	if $error ~~ X::Cro::HTTP::Client::Timeout {
		return X::MCP::Client::Timeout.new(
			seconds => ($budget > 0 ?? $budget !! $!connect-timeout), :$method, :$id,
		);
	}

	# Connection refused, connection reset, DNS failure, TLS handshake failure:
	# the endpoint is not answering, which for the era probe is a dead wire
	# rather than evidence about the server's protocol version.
	X::MCP::Client::ServerGone.new(command => $!url, stderr-tail => first-line($error));
}

method !budget($timeout --> Real:D) {
	my $wanted = $timeout ~~ Real:D ?? $timeout !! $!default-timeout;
	$wanted > 0 ?? $wanted !! 0;
}

method !warn(Str:D $message --> Nil) {
	return without &!on-warn;
	CATCH { default { } }   # a warning hook that throws is not worth a crash
	&!on-warn($message);
	Nil;
}

# === Exported seams ===

#| Encode one value for an HTTP header, using the C<=?base64?...?=> sentinel
#| when it cannot travel as-is.
#|
#| Per 2026-07-28 Value Encoding: header field values are visible ASCII
#| (0x21-0x7E), space and horizontal tab, so a value with non-ASCII characters,
#| control characters or leading/trailing whitespace is base64-encoded from its
#| UTF-8 form. A plain-ASCII value that merely I<looks> like the sentinel is
#| encoded too, "to avoid ambiguity". The markers are lowercase and
#| case-sensitive.
sub header-encode(Str:D $value --> Str:D) is export {
	return $value if header-safe($value) && $value !~~ &sentinel;
	'=?base64?' ~ MIME::Base64.encode-str($value, :oneline) ~ '?=';
}

#| True when a value may travel in a header untouched.
sub header-safe(Str:D $value --> Bool:D) is export {
	if $value.chars {
		return False if $value.substr(0, 1) eq (' ' | "\t");
		return False if $value.substr(*- 1) eq (' ' | "\t");
	}
	for $value.ords -> $ord {
		return False unless (0x21 <= $ord <= 0x7E) || $ord == 0x20 || $ord == 0x09;
	}
	True;
}

#| Every header one outbound message implies, as a list of C<Pair>s:
#| C<Content-Type> aside (Cro sets that), the C<Accept> both content types
#| ("The client MUST include an Accept header listing both application/json and
#| text/event-stream"), C<MCP-Protocol-Version> copied from the body's C<_meta>,
#| C<Mcp-Method>, C<Mcp-Name> where the method has one, and the C<Mcp-Param-*>
#| mirrors for whichever arguments the tool annotated.
#|
#| The protocol version is B<copied from the body>, never guessed: the two must
#| match or the server rejects the request with C<-32020>. C<$protocol-version>
#| is the fallback for a message that carries no C<_meta> at all.
sub request-headers(%msg, :%annotations, Str :$protocol-version --> List:D) is export {
	my Str $method = %msg<method> ~~ Str:D ?? %msg<method> !! '';
	my %params = %msg<params> ~~ Associative ?? %msg<params>.Hash !! {};
	my %meta = %params<_meta> ~~ Associative ?? %params<_meta>.Hash !! {};

	my $version = %meta{META-PROTOCOL-VERSION} ~~ Str:D
		?? %meta{META-PROTOCOL-VERSION}
		!! ($protocol-version // MODERN-PROTOCOL-VERSION);

	my @headers =
		# Not sentinel-encoded: the server compares this one byte for byte
		# against the body's _meta, without decoding.
		'MCP-Protocol-Version' => $version,
		'Mcp-Method'           => header-encode($method),
		'Accept'               => 'application/json, text/event-stream';

	with name-for-method($method, %params) -> $name {
		@headers.push('Mcp-Name' => header-encode($name));
	}

	@headers.append(param-headers(%params<arguments>, %annotations))
		if $method eq 'tools/call' && %annotations.elems;

	@headers.List;
}

#| The C<Mcp-Param-*> headers an argument hash produces under one tool's
#| annotations. A path with no value at it — absent, or JSON C<null> — produces
#| no header, which is exactly what the specification's table says
#| ("Parameter value is null: Client MUST omit the header").
sub param-headers($arguments, %annotations --> List:D) is export {
	my %args = $arguments ~~ Associative ?? $arguments.Hash !! {};
	my @headers;

	for %annotations.keys.sort -> $header-name {
		my @path = %annotations{$header-name}.list;
		next unless @path.elems;

		my $value = value-at(%args, @path);
		next without $value;

		@headers.push("Mcp-Param-$header-name" => header-encode(header-string($value)));
	}

	@headers.List;
}

#| Validate one tool definition's C<x-mcp-header> annotations and, when they are
#| all sound, say where each header's value lives.
#|
#| Returns C<< { valid => Bool, reason => Str, headers => { name => (path) } } >>.
#| The rules, verified 2026-08-08 against
#| L<https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#schema-extension>,
#| are that an C<x-mcp-header> value:
#|
#| =item B<MUST NOT> be empty;
#| =item B<MUST> match HTTP field-name token syntax (C<1*tchar>, RFC 9110 §5.1),
#|       which also rules out the CR and LF a header injection would need;
#| =item B<MUST> be case-insensitively unique within the C<inputSchema>;
#| =item B<MUST> only be applied to a primitive-typed property — C<string>,
#|       C<integer> or C<boolean>, and pointedly not C<number>;
#| =item B<MUST> only be applied to a property that is I<statically reachable>
#|       from the schema root through a chain of C<properties> keys alone.
#|       Nested objects are fine; C<items>, C<oneOf>/C<anyOf>/C<allOf>/C<not>,
#|       C<if>/C<then>/C<else> and C<$ref> are not, and "an x-mcp-header
#|       annotation anywhere else makes the annotation — and thus the tool
#|       definition — invalid".
sub tool-header-annotations(%tool --> Hash:D) is export {
	my @found;
	collect-annotations(%tool<inputSchema>, (), True, @found);

	my %headers;
	my %taken;

	for @found -> %annotation {
		my $name = %annotation<name>;
		my $where = %annotation<path>.elems ?? %annotation<path>.join('.') !! 'the schema root';

		return rejected("the x-mcp-header on $where is not a string")
			unless $name ~~ Str:D;
		return rejected("the x-mcp-header on $where is empty")
			unless $name.chars;
		return rejected("the x-mcp-header '$name' on $where is not an HTTP field-name token")
			unless http-token($name);
		return rejected("the x-mcp-header '$name' is on $where, which is not statically "
			~ 'reachable from the schema root through properties alone')
			unless %annotation<reachable>;
		return rejected("the x-mcp-header '$name' is on $where, whose type is "
			~ ('\'' ~ (%annotation<type> // 'unset') ~ '\'')
			~ ' rather than string, integer or boolean')
			unless %annotation<type> ~~ Str:D && PRIMITIVE-TYPES{%annotation<type>};
		return rejected("the x-mcp-header '$name' is used more than once (names are "
			~ 'compared case-insensitively)')
			if %taken{$name.lc};

		%taken{$name.lc} = True;
		%headers{$name} = %annotation<path>;
	}

	{ valid => True, reason => Str, headers => %headers };
}

#| What a response's status and content type mean: C<'sse'>, C<'json'>,
#| C<'accepted'> (202, a notification acknowledgement) or C<'error'>.
sub response-kind(Int:D $status, $content-type --> Str:D) is export {
	return 'accepted' if $status == 202;

	if $status == 200 {
		my $type = ($content-type // '').Str.lc;
		return $type.contains('text/event-stream') ?? 'sse' !! 'json';
	}

	'error';
}

#| The failure an unsuccessful response deserves.
#|
#| A modern server puts a JSON-RPC error object in the body of its 400s and
#| 404s, and both matter: C<-32601> under a 404 is "no such method",
#| C<-32022> under a 400 is "wrong protocol version, here are mine", and the era
#| machine reads the code and the C<data> to decide what to do next. A body that
#| is not a recognisable JSON-RPC error at all — an HTML error page from a proxy,
#| an empty 405 — becomes a plain protocol error naming the status, which the
#| era machine reads as "not a modern server".
sub error-for-status(Int:D $status, $body --> X::MCP::Client::Protocol:D) is export {
	my $text = ($body // '').Str;
	my %in = parse-inbound($text);

	return protocol-error(%in<error>)
		if %in<kind> eq 'response' && (%in<error>:exists);

	# A JSON-RPC error response with no id member at all is malformed, and
	# parse-inbound says so -- but the error object inside it is still the
	# server's diagnosis, and throwing it away would lose the code.
	my $message = %in<message>;
	return protocol-error($message<error>.Hash)
		if $message ~~ Associative && $message<error> ~~ Associative;

	my $snippet = $text.trim.lines.head // '';
	$snippet = $snippet.substr(0, 200) ~ '...' if $snippet.chars > 200;

	X::MCP::Client::Protocol.new(
		detail => "the server answered HTTP $status"
			~ ($snippet.chars ?? ": $snippet" !! ' with no readable body'),
	);
}

# === Internals behind the seams ===

#| The response object whatever the status: Cro breaks the promise for 4xx and
#| 5xx, and the response we came for is hanging off the exception.
my sub response-of(Promise:D $posted --> Promise:D) {
	$posted.then(sub ($promise) {
		if $promise.status === Kept {
			$promise.result;
		}
		else {
			my $cause = $promise.cause;
			$cause ~~ X::Cro::HTTP::Error ?? $cause.response !! $cause.rethrow;
		}
	});
}

#| The response body as text, decoded here rather than by Cro.
#|
#| JSON-RPC is UTF-8 by definition and MCP servers do not send a charset
#| parameter, which puts Cro's C<body-text> on its "try utf-8, then latin-1"
#| path — and that path has no C<last>, so the latin-1 attempt (which cannot
#| fail, whatever the bytes) always overwrites the correct decode. Every
#| non-ASCII tool name, resource URI and result string would come back as
#| mojibake. Latin-1 is still the fallback here, for the HTML error page a proxy
#| in front of the server might answer with.
my sub body-text($response --> Str:D) {
	my $blob = try await $response.body-blob;
	return '' without $blob;
	(try $blob.decode('utf-8')) // (try $blob.decode('latin-1')) // '';
}

my sub protocol-error($error --> X::MCP::Client::Protocol:D) {
	my %error = $error ~~ Associative ?? $error.Hash !! {};
	X::MCP::Client::Protocol.new(
		detail => (%error<message> ~~ Str:D ?? %error<message> !! 'the server returned an error'),
		code   => (%error<code> ~~ Real:D ?? %error<code>.Int !! Int),
		data   => %error<data>,
	);
}

#| The first line of whatever went wrong, always a defined string: what
#| X::MCP::Client::ServerGone reports as the peer's last words.
my sub first-line($error --> Str:D) {
	my $text = $error ~~ Exception ?? $error.message !! ($error // '').Str;
	($text.lines.head // '').Str;
}

my sub rejected(Str:D $reason --> Hash:D) {
	{ valid => False, reason => $reason, headers => {} };
}

my sub name-for-method(Str:D $method, %params) {
	my $field = %NAME-FIELD-FOR-METHOD{$method};
	return Str without $field;
	%params{$field} ~~ Str:D ?? %params{$field} !! Str;
}

#| The value at an exact property path, or Nil when the path does not lead to
#| one. "Header extraction is defined as reading the instance value at the exact
#| property path of the annotated property."
my sub value-at(%args, @path) {
	my $node = %args;
	for @path -> $step {
		return Nil unless $node ~~ Associative;
		return Nil unless $node{$step}:exists;
		$node = $node{$step};
	}
	$node;
}

#| A value's string form for a header. Booleans are lowercase words and integers
#| are decimal, per Value Encoding.
#|
#| An integer outside JavaScript's safe range is mirrored anyway: the
#| specification's safe-range rule constrains what a server should annotate, and
#| dropping the header instead would make us the "non-conforming client" whose
#| request the server MUST reject.
my sub header-string($value --> Str:D) {
	# Bool is checked first on purpose: Raku's Bool is an Int-backed enum, so
	# checking Int first would send '1' where the protocol wants 'true'.
	return $value ?? 'true' !! 'false' if $value ~~ Bool;
	$value.Str;
}

my sub http-token(Str:D $value --> Bool:D) {
	return False unless $value.chars;
	for $value.comb -> $char {
		my $ord = $char.ord;
		next if 0x30 <= $ord <= 0x39;
		next if 0x41 <= $ord <= 0x5A;
		next if 0x61 <= $ord <= 0x7A;
		return False unless TCHAR-SYMBOLS{$char};
	}
	True;
}

#| Find every C<x-mcp-header> in a schema, wherever it hides, recording whether
#| it sits on a statically reachable property. Everything that is not a
#| C<properties> edge is still walked — an annotation inside C<items> or
#| C<oneOf> has to be I<found> to be rejected.
my sub collect-annotations($node, @path, Bool:D $reachable, @found --> Nil) {
	return unless $node ~~ Associative;

	if $node<x-mcp-header>:exists {
		@found.push({
			name      => $node<x-mcp-header>,
			path      => @path.List,
			type      => $node<type>,
			# An annotation on the schema root itself names no property, so it
			# is no more reachable than one inside a $ref.
			reachable => $reachable && @path.elems > 0,
		});
	}

	my $properties = $node<properties>;
	if $properties ~~ Associative {
		for $properties.keys.sort -> $key {
			collect-annotations($properties{$key}, (|@path, $key), $reachable, @found);
		}
	}

	for $node.keys.sort -> $key {
		next if $key eq 'properties' || $key eq 'x-mcp-header';
		my $child = $node{$key};

		if $child ~~ Associative {
			collect-annotations($child, @path, False, @found);
		}
		elsif $child ~~ Positional {
			for $child.list -> $item { collect-annotations($item, @path, False, @found) }
		}
	}
	Nil;
}
