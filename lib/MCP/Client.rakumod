=begin pod

=head1 NAME

MCP::Client - talk to an MCP server, in either protocol era

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client;

my $mcp = MCP::Client.connect-stdio(
	command      => 'my-mcp-server',
	args         => ['--stdio'],
	client-name  => 'my-agent',
	on-elicit    => -> %request { ask-the-user(%request<params>) },
);

say $mcp.era;                      # modern | legacy -- probed on first use
say $mcp.server-info<name>;

for $mcp.list-tools -> %tool {
	say "%tool<name>: %tool<description>";
}

my %result = $mcp.call-tool('search', { query => 'raku' });
say .<text> for %result<content>.grep({ .<type> eq 'text' });

$mcp.close;
=end code

=head1 DESCRIPTION

An MCP client with one job: make a third-party MCP server usable from Raku
without the caller having to care which revision of the protocol that server
speaks, whether it wants a handshake, whether its answers may be cached, or
whether it will interrupt a tool call to ask a question.

=head2 Protocol eras

There are two of them, and they are not compatible:

=item B<Legacy> (C<2025-11-25> and earlier) opens with an C<initialize>
      handshake. Version and capabilities are agreed once, for the connection.
=item B<Modern> (C<2026-07-28>) has no handshake and no session. Every single
      request carries its own protocol version, client identity and client
      capabilities in C<params._meta>, so any request may be served by any
      instance of the server.

The client works out which it is talking to on the first call that needs the
answer, and remembers it for the life of the connection. The probe is a
C<server/discover> request under a short budget (C<:$probe-timeout>, five
seconds by default, deliberately separate from the request timeout — a legacy
server may simply never answer it):

=item a C<DiscoverResult> whose C<supportedVersions> overlaps ours ⇒ B<modern>,
      at the newest version we both speak;
=item C<-32022 UnsupportedProtocolVersion> ⇒ the server is certainly modern; if
      its C<data.supported> names a version we speak we probe again at that
      version, and if it names only legacy versions we fall back;
=item any other JSON-RPC error, a timeout, or a reply that is not a
      C<DiscoverResult> at all ⇒ B<legacy>: send C<initialize>, check the
      version that comes back, and send C<notifications/initialized>.

A dead transport is not an era signal: if the probe fails because the server
process is gone, the connection was closed, or the caller cancelled, that
failure is raised rather than misread as "must be a legacy server".

=head2 Multi round-trip requests

A modern server may answer C<tools/call>, C<resources/read> or C<prompts/get>
with C<resultType: "input_required"> instead of a result: it needs something
from the client — a question answered, an LLM consulted, a root list — before
it can finish. The client fulfils those requests and B<retries> the original
call under a fresh id, carrying the answers and the server's opaque
C<requestState> back with it. That is the whole reason the modern protocol can
be stateless, and it is handled here transparently: C<call-tool> returns the
final result, however many round trips it took.

Wire hooks for the kinds of input you are willing to serve:

=begin code :lang<raku>
my $mcp = MCP::Client.connect-stdio(
	command       => 'server',
	on-elicit     => -> %request { { action => 'accept', content => ask(%request) } },
	on-sample     => -> %request { my-llm(%request<params>) },
	on-list-roots => -> %request { { roots => [{ uri => 'file:///srv', name => 'srv' }] } },
);
=end code

Each hook is called with the server's request (C<method> and C<params>) and
returns the body of the matching result. B<Which hooks you set is what the
client declares as its capabilities> — the server is forbidden from asking for
input you have not declared, so an unset hook is both a refusal and a
promise never to be asked. Refusal is still handled: an unset hook, or one that
throws, declines (C<< { action => 'decline' } >> for elicitation, an empty root
list for roots) rather than failing the call.

A server that never stops asking cannot pin the client: after
C<:$max-input-rounds> retries (eight by default) the call fails with
C<X::MCP::Client::InputLoopExceeded>.

=head2 Caching

C<tools/list>, C<prompts/list>, C<resources/list> and C<resources/read> are
cached exactly as far as the server permits, using the C<ttlMs> it attaches to
each result. Legacy servers make no such promise, so nothing they say is ever
cached. Pass C<:refresh> to any of those methods to bypass and re-fetch.

=head2 Blocking and async

Every method blocks. Every method also has an C<-async> twin returning a
C<Promise>, so a caller can have several calls in flight — the transports
multiplex, and correlation is by JSON-RPC id:

=begin code :lang<raku>
my @answers = await (
	$mcp.call-tool-async('search', { query => 'a' }),
	$mcp.call-tool-async('search', { query => 'b' }),
);
=end code

=head2 Feeding an LLM

C<tools-for-llm> renders the server's catalogue as OpenAI-style function
declarations, and C<execute-tool-calls> takes the tool calls a model asked for
and runs them. The pair is deliberately identical to C<MCP::Server>'s, so a
remote server and a local toolkit are interchangeable to the caller — and
C<MCP::Client::Registry> aggregates any number of either behind one prefix
namespace:

=begin code :lang<raku>
use LLM::Chat::ToolLoop;

my $loop = LLM::Chat::ToolLoop.new(
	backend       => $backend,
	tools         => $mcp.tools-for-llm,
	execute-tools => -> @calls { $mcp.execute-tool-calls(@calls) },
);
=end code

C<execute-tool-calls> B<never throws>. A malformed call, arguments that are not
JSON, a tool the server does not have, a tool that failed, a timeout, an
exhausted multi round-trip loop, even a connection that has died — each becomes
a result with C<is_error> set and the reason as its C<content>, because a model
that can read what went wrong can try something else, and an exception thrown
into the middle of a tool round cannot be recovered from at all.

=head2 Errors

Everything this client raises is an C<X::MCP::Client> (see
L<MCP::Client::Exceptions>). A JSON-RPC error from the server becomes an
C<X::MCP::Client::Protocol> carrying the wire C<code> and C<data>:

=begin code :lang<raku>
{
	CATCH {
		when X::MCP::Client::Timeout   { note "too slow: {.message}" }
		when X::MCP::Client::Protocol  { note "server refused: {.message} ({.code})" }
		when X::MCP::Client::ServerGone { note "server died: {.stderr-tail}" }
	}
	$mcp.call-tool('flaky', {});
}
=end code

=head2 Notifications and logging

C<notifications> is a C<Supply> of every notification the server sends —
progress, log messages, list-changed. C<:&on-log> is a shortcut for the log
ones, and C<:$log-level> asks a modern server to filter them at source:

=begin code :lang<raku>
my $mcp = MCP::Client.connect-stdio(
	command   => 'server',
	log-level => 'info',
	on-log    => -> %params { note "[%params<level>] %params<data>" },
);
$mcp.notifications.tap: -> %note { say "server said %note<method>" };
=end code

B<Set C<:$log-level> if you want log notifications from a modern server at
all.> 2026-07-28 removed C<logging/setLevel> in favour of the per-request
C<_meta> level, and a server B<MUST NOT> emit C<notifications/message> for a
request that did not carry one — so an C<on-log> hook without a C<log-level>
will simply never fire.

=head2 Progress

A long tool call can say how it is getting on. Progress is opt-in from this
end — a request carries a C<progressToken> when the caller wants to be kept
posted, and a server may not report on one that did not — so C<:&on-progress>
both asks for it and receives it, for every call the LLM bridge runs:

=begin code :lang<raku>
my $mcp = MCP::Client.connect-stdio(
	command     => 'server',
	on-progress => -> %p {
		$ui.progress(%p<tool-call-id>, %p<progress>, %p<total>, %p<message>);
	},
);
=end code

The payload is C<< { tool-call-id, progress, total?, message? } >>:
C<tool-call-id> is the id of the call the model made, which is what ties the
line to the tool card it belongs on, and C<total> and C<message> are there only
when the server sent them. The bridge mints a fresh token per call — not the
call id, which a retried call would reuse — and forgets it the moment the call
answers, so a report that arrives late, or one quoting a token from somewhere
else, is dropped rather than attributed to the wrong tool.

B<The hook fires on the reader thread>, ahead of the answer it belongs to.
Treat it as a leaf: push the payload somewhere and return. See C<:&on-progress>
for the full contract.

Outside the bridge, C<call-tool> takes a C<:$progress-token> of your own and
the notifications arrive on C<notifications> like any other.

=end pod

use JSON::Fast;

use MCP::Server::Protocol;

use MCP::Client::Cache;
use MCP::Client::Exceptions;
use MCP::Client::Protocol;
use MCP::Client::Transport;

unit class MCP::Client;

# The methods a 2026-07-28 server may answer with an InputRequiredResult.
# Verified 2026-08-08 against
# https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
# ("Supported Requests": prompts/get, resources/read, tools/call -- "Servers
# MUST NOT send InputRequiredResult responses on any other client requests").
constant MRTR-METHODS = Set.new(<tools/call resources/read prompts/get>);

# Keys the protocol puts in a result that a caller of the typed API has no use
# for: bookkeeping for the era machine, the cache and the round-trip loop, all
# of which have already been acted on by the time a result is handed back.
constant ENVELOPE-KEYS = <resultType _meta ttlMs cacheScope requestState inputRequests>;

#| The wire underneath this client. Supplied directly when embedding a
#| transport of your own (or a test double); C<connect-stdio> / C<connect-http>
#| build one for you.
has MCP::Client::Transport:D $.transport is required;

#| Reported to the server as C<clientInfo>, in both eras. Servers use it for
#| logging and diagnostics only — it is self-reported and unverified.
has Str:D $.client-name = 'raku-mcp-client';
has Str:D $.client-version = '0.1.0';

#| The modern protocol versions this client will speak, best first. The legacy
#| era is always available as a fallback and must not be named here: it is
#| reached by handshake, not by version stamp.
has Str:D @.protocol-versions = (MODERN-PROTOCOL-VERSION,);

#| Seconds before an ordinary request gives up. C<0> disables the budget.
has Real:D $.request-timeout = 60;

#| Seconds before the era probe gives up and concludes it is talking to a
#| legacy server. Short on purpose and separate from C<$.request-timeout>: a
#| legacy server does not answer C<server/discover> at all, and waiting a full
#| minute to find that out would make every connection to one feel broken.
has Real:D $.probe-timeout = 5;

#| How many times a multi round-trip request may be retried before
#| C<X::MCP::Client::InputLoopExceeded>.
has UInt:D $.max-input-rounds = 8;

#| Called with a server C<elicitation/create> request; returns an
#| C<ElicitResult> body, e.g. C<< { action => 'accept', content => { ... } } >>.
has &.on-elicit;

#| Called with a server C<sampling/createMessage> request; returns a
#| C<CreateMessageResult> body — C<model>, C<role> and C<content> are required
#| by the schema.
has &.on-sample;

#| Called with a server C<roots/list> request; returns a C<ListRootsResult>
#| body, C<< { roots => [ { uri => ..., name => ... }, ... ] } >>.
has &.on-list-roots;

#| Called with the C<params> of every C<notifications/message> the server
#| sends. A shortcut for tapping C<notifications> and filtering.
has &.on-log;

#| Called as a tool call the LLM bridge is running reports progress:
#|
#|   { tool-call-id => 'call_abc', progress => 3e0, total => 10e0, message => 'file 3' }
#|
#| C<tool-call-id> is the id of the call the model made, so a UI can put the
#| line on the right card; C<total> and C<message> are present only when the
#| server sent them. Wiring this hook is also what B<asks> for progress: the
#| bridge attaches a progress token to a tool call only when somebody is
#| listening, since a server told to report progress does the work of reporting
#| it. (C<call-tool> can be given a C<:$progress-token> of your own, in which
#| case the notifications arrive on C<notifications> and this hook is not
#| involved.)
#|
#| B<It fires on the client's reader thread>, in front of the answer to the call
#| it belongs to, so treat it as a leaf: hand the payload to a queue or a store
#| and return. Work done here delays every message behind it on the connection,
#| and calling back into this client from it will deadlock on the in-flight
#| request. A hook that throws is reported through C<:&on-warn> and does not
#| disturb the call.
has &.on-progress;

#| Called with a one-line diagnostic when the client papers over something the
#| caller might want to know about — an input hook that threw, a notification
#| subscriber that died. Defaults to writing to C<$*ERR>.
has &.on-warn = -> Str:D $message { note "[MCP::Client] $message" };

#| Asks a modern server to send log notifications no less severe than this
#| (an RFC 5424 level). Stamped into every request's C<_meta>; legacy servers
#| are told through C<logging/setLevel> instead, which this client leaves to
#| the caller.
has Str $.log-level;

#| Client capabilities to declare, overriding the ones derived from which hooks
#| are wired. Only needed when a hook can do more than the derivation assumes —
#| URL-mode elicitation, say.
has %.client-capabilities;

#| The result cache. Injectable so a caller can share one, or hand in a cache
#| with a virtual clock.
has MCP::Client::Cache:D $.cache = MCP::Client::Cache.new;

has Lock     $!lock .= new;
has Lock     $!probe-lock .= new;
has Int      $!next-id = 0;

# progress token => the id of the tool call it was minted for, for as long as
# that call is in flight. Its own lock: the reader thread reads this table for
# every notifications/progress that arrives, and must not queue behind an era
# probe or an id being minted to do it.
has Lock     $!progress-lock .= new;
has          %!progress-calls;
has Int      $!next-progress = 0;
has Bool     $!closed = False;
has Str      $!era;
has Str      $!negotiated-version;
has Str      $!instructions;
has          %!server-info;
has          %!capabilities;
has          %!discovery;
has Str      @!supported-versions;
has          %!declared-capabilities;
has Supplier $!notifications .= new;
has          &!notification-sink;

submethod TWEAK(*%rest) {
	# .new silently ignores named arguments it does not recognise, which turns
	# a typo in a hook name into a client that quietly never elicits. Catching
	# it here costs one Set build per connection.
	my $known = self.^attributes.map({ .name.substr(2) }).Set;
	my @unknown = %rest.keys.grep({ !$known{$_} }).sort;
	die X::MCP::Client.new(
		detail => 'unknown option' ~ (@unknown.elems > 1 ?? 's' !! '')
			~ ': ' ~ @unknown.join(', '),
	) if @unknown;

	die X::MCP::Client.new(detail => 'protocol-versions must name at least one version')
		unless @!protocol-versions.elems;

	for @!protocol-versions -> $version {
		die X::MCP::Client.new(detail => 'protocol-versions entries must be non-empty strings')
			unless $version.chars;
		# The legacy era is not a version you can stamp on a request: it is a
		# handshake, and a request carrying _meta is modern by definition. A
		# client that lists it here has confused "I can fall back" (always
		# true) with "I can speak this modernly" (never true).
		die X::MCP::Client::UnsupportedVersion.new(
			requested => $version,
			supported => MODERN-PROTOCOL-VERSIONS.list,
		) if $version eq LEGACY-PROTOCOL-VERSION;
	}

	if $!log-level.defined && !(%LOG-LEVELS{$!log-level}:exists) {
		die X::MCP::Client.new(
			detail => "unknown log level '$!log-level' (expected one of "
				~ %LOG-LEVELS.keys.sort.join(', ') ~ ')',
		);
	}

	die X::MCP::Client.new(detail => 'max-input-rounds must be at least 1')
		if $!max-input-rounds < 1;
	die X::MCP::Client.new(detail => 'request-timeout cannot be negative')
		if $!request-timeout < 0;
	die X::MCP::Client.new(detail => 'probe-timeout cannot be negative')
		if $!probe-timeout < 0;

	%!declared-capabilities = %!client-capabilities.elems
		?? %!client-capabilities.Hash
		!! self!derive-capabilities;

	&!notification-sink = -> %note { self!receive-notification(%note) };
}

# === Construction ===

#| Connect to a server run as a child process, speaking JSON-RPC over its
#| stdin and stdout.
#|
#| C<$command> is executed directly — there is no shell, so no quoting, no
#| globbing and no C<PATH> extension magic. On Windows a C<.cmd> shim (which
#| is what npm installs) is a batch script that only C<cmd.exe> can run, so
#| spawn the interpreter: C<< command => 'cmd.exe', args => ['/c', 'npx', ...] >>.
#| A real C<.exe> may be named directly.
#|
#| Every option C<MCP::Client.new> takes may be passed through: hooks,
#| timeouts, C<client-name>, and so on. The transport's own knobs ride along
#| too — C<:&on-stderr>, C<:$kill-grace>, C<:$stderr-lines> and
#| C<:$inherit-env> reach the spawned transport rather than the client — and a
#| C<:&on-warn> serves both: the client keeps it for its own diagnostics and
#| the transport reports wire-level ones (dropped lines, late answers) through
#| it as well. C<:$transport> substitutes a ready-made transport for the
#| spawned one, which is how the test suite drives the client without a
#| subprocess; the transport knobs are refused in that case rather than
#| silently ignored.
method connect-stdio(
	Str :$command, :@args, :%env, Str :$cwd,
	:&on-stderr, Real :$kill-grace, UInt :$stderr-lines, Bool :$inherit-env,
	MCP::Client::Transport :$transport,
	*%opts
	--> MCP::Client:D
) {
	my %transport-args;
	%transport-args<on-stderr>    = &on-stderr    with &on-stderr;
	%transport-args<kill-grace>   = $kill-grace   with $kill-grace;
	%transport-args<stderr-lines> = $stderr-lines with $stderr-lines;
	%transport-args<inherit-env>  = $inherit-env  with $inherit-env;
	%transport-args<on-log>       = %opts<on-warn> if %opts<on-warn>:exists;

	my $wire = $transport // do {
		die X::MCP::Client.new(detail => 'connect-stdio needs a :$command')
			unless $command.defined && $command.chars;
		load-transport('MCP::Client::Transport::Stdio', 'stdio').new(
			:$command, :@args, :%env, :$cwd, |%transport-args,
		);
	};

	# on-warn is shared; the rest configure a transport this caller did not let
	# us build.
	if $transport.defined {
		my @stranded = <on-stderr kill-grace stderr-lines inherit-env>.grep({
			%transport-args{$_}:exists
		});
		die X::MCP::Client.new(
			detail => 'connect-stdio was given both a ready-made :$transport and '
				~ 'transport options it cannot apply to it: ' ~ @stranded.join(', '),
		) if @stranded;
	}

	MCP::Client.new(transport => $wire, |%opts);
}

#| Connect to a server over Streamable HTTP. Modern era only: this client does
#| not implement the legacy HTTP session transport.
#|
#| The transport's knobs ride along as they do for stdio: C<:$http-version>,
#| C<:$persistent> and C<:$connect-timeout> reach the transport, and a
#| C<:&on-warn> serves both client and transport diagnostics. C<:$transport>
#| substitutes a ready-made transport, exactly as for C<connect-stdio>, and
#| likewise refuses stranded transport options.
method connect-http(
	Str :$url, :%headers,
	:$http-version, Bool :$persistent, Real :$connect-timeout,
	MCP::Client::Transport :$transport,
	*%opts
	--> MCP::Client:D
) {
	my %transport-args;
	%transport-args<http-version>    = $http-version    with $http-version;
	%transport-args<persistent>      = $persistent      with $persistent;
	%transport-args<connect-timeout> = $connect-timeout with $connect-timeout;
	%transport-args<on-warn>         = %opts<on-warn> if %opts<on-warn>:exists;

	my $wire = $transport // do {
		die X::MCP::Client.new(detail => 'connect-http needs a :$url')
			unless $url.defined && $url.chars;
		load-transport('MCP::Client::Transport::HTTP', 'HTTP').new(
			:$url, :%headers, |%transport-args,
		);
	};

	if $transport.defined {
		my @stranded = <http-version persistent connect-timeout>.grep({
			%transport-args{$_}:exists
		});
		die X::MCP::Client.new(
			detail => 'connect-http was given both a ready-made :$transport and '
				~ 'transport options it cannot apply to it: ' ~ @stranded.join(', '),
		) if @stranded;
	}

	MCP::Client.new(transport => $wire, |%opts);
}

# Transports are loaded on demand, never `use`d: the HTTP one drags Cro in, and
# a stdio client should not pay that at startup. The require's return value is
# bound rather than looked up again through ::('...') -- `use`ing a sibling of
# the MCP::Client namespace installs a package stub that a later ::('...')
# resolves against instead of the real GLOBAL, and the symbol is not found.
my sub load-transport(Str:D $class-name, Str:D $kind) {
	my \transport-class = try (require ::($class-name));
	# A transport arrives here as its type object, whose .defined is False --
	# so definedness cannot be the test, or every transport would look missing.
	# A require that lost hands back Nil; one whose module loaded and then blew
	# up hands back a Failure.
	if transport-class === Nil || transport-class ~~ Failure {
		die X::MCP::Client.new(
			detail => "the $kind transport ($class-name) is not available in this build"
				~ ($! ?? ': ' ~ $!.message.lines.head !! ''),
		);
	}
	transport-class;
}

# === Era ===

#| Which protocol era this server speaks: C<'modern'> or C<'legacy'>. Probes on
#| the first call and remembers the answer for the life of the connection —
#| the era is a property of the server, not of a request.
method era(--> Str:D) {
	self!ensure-era;
}

#| What the server told us about itself: for a modern server the
#| C<server/discover> document, for a legacy one the C<initialize> result.
#| Both carry C<capabilities>, and C<instructions> when the server offers them.
method discover(--> Hash) {
	self!ensure-era;
	%!discovery.Hash;
}

#| The server's name and version, or an empty hash if it named neither.
method server-info(--> Hash) {
	self!ensure-era;
	%!server-info.Hash;
}

#| The server's capability declaration: which of C<tools>, C<resources>,
#| C<prompts> (and, on a legacy server, C<logging>) it offers.
method capabilities(--> Hash) {
	self!ensure-era;
	%!capabilities.Hash;
}

#| The server's usage instructions for a model, or Str if it published none.
method instructions(--> Str) {
	self!ensure-era;
	$!instructions;
}

#| The protocol version in force: the negotiated modern version, or
#| C<2025-11-25> once the legacy handshake has completed.
method protocol-version(--> Str) {
	self!ensure-era;
	$!negotiated-version;
}

#| Every version the server said it speaks. Empty for a legacy server, which
#| answers with one version rather than a list.
method supported-versions(--> List:D) {
	self!ensure-era;
	@!supported-versions.List;
}

#| The capabilities this client declares to the server, derived from which
#| hooks are wired unless C<%.client-capabilities> overrode them.
method declared-capabilities(--> Hash:D) {
	%!declared-capabilities.Hash;
}

method !ensure-era(--> Str:D) {
	self!check-open;

	my $known = $!lock.protect: { $!era };
	return $known with $known;

	$!probe-lock.protect: {
		# Re-checked under the probe lock: two threads racing to make the first
		# call must produce one probe, not two.
		self!probe without $!lock.protect({ $!era });
	}

	my $era = $!lock.protect: { $!era };
	die X::MCP::Client.new(detail => 'era probe finished without deciding an era')
		without $era;
	$era;
}

method !probe(--> Nil) {
	my Str $version = @!protocol-versions[0];
	my %tried;

	loop {
		%tried{$version} = True;

		my %result;
		my $failure;
		{
			CATCH { default { $failure = $_ } }
			%result = self!send(
				'server/discover', {},
				era => 'modern', protocol-version => $version, timeout => $!probe-timeout,
			);
		}

		with $failure {
			# A dead wire says nothing about the era. Falling back to
			# `initialize` here would replace a precise diagnosis ("the server
			# exited with code 127") with a second, more confusing failure.
			$failure.rethrow if $failure ~~ X::MCP::Client::ServerGone
				|| $failure ~~ X::MCP::Client::TransportClosed
				|| $failure ~~ X::MCP::Client::Cancelled;

			my $code = $failure ~~ X::MCP::Client::Protocol ?? $failure.code !! Int;

			# Only a modern server can produce a modern error code, so this
			# branch has settled the era even though the request failed.
			if $code.defined && is-modern-error({ code => $code }) {
				if $code == UNSUPPORTED_PROTOCOL_VERSION {
					my @supported = versions-from($failure.data);
					my $next = self!best-modern(@supported);

					if $next.defined && !%tried{$next} {
						$version = $next;
						next;
					}

					# A modern server whose supported list names only versions
					# we cannot speak. If one of them is the legacy era we can
					# still talk to it -- through the handshake, not through
					# _meta.
					if @supported.grep({ $_ eq LEGACY-PROTOCOL-VERSION }).elems {
						self!legacy-handshake;
						return;
					}

					die X::MCP::Client::UnsupportedVersion.new(
						requested => $version, supported => @supported,
					);
				}

				# -32020 / -32021 on the probe: modern, but it told us nothing
				# about itself. The catalog calls will fill that in, or fail
				# loudly enough to diagnose.
				self!adopt-modern($version, {});
				return;
			}

			# Everything else -- method-not-found, a timeout, a parse error, a
			# legacy server's idea of an error for an unknown method -- means
			# the server is not modern.
			self!legacy-handshake;
			return;
		}

		my @supported = %result<supportedVersions> ~~ Positional
			?? %result<supportedVersions>.grep(Str:D).map(*.Str).list
			!! ();
		my $chosen = self!best-modern(@supported);

		# No overlap covers three cases that look different and are not: a
		# reply that is not a DiscoverResult at all, an empty supportedVersions
		# (which is what MCP::Server answers when it is configured for the
		# legacy era only), and a genuinely disjoint list. In each the server
		# has declined to offer us a modern version, so we ask it the old way.
		without $chosen {
			self!legacy-handshake;
			return;
		}

		self!adopt-modern($chosen, %result, :@supported);
		return;
	}
}

# The first version we prefer that the server also named. Our list is ordered
# best-first, so preference is ours, not the server's.
method !best-modern(@supported --> Str) {
	my $offered = @supported.Set;
	@!protocol-versions.first({ $offered{$_} }) // Str;
}

# The `supported` list out of an UnsupportedProtocolVersionError's data, which
# is server-controlled and therefore may be anything at all.
my sub versions-from($data --> List:D) {
	return () unless $data ~~ Associative;
	my $supported = $data<supported>;
	return () unless $supported ~~ Positional;
	$supported.grep(Str:D).map(*.Str).list;
}

method !adopt-modern(Str:D $version, %result, :@supported --> Nil) {
	my %meta = %result<_meta> ~~ Associative ?? %result<_meta>.Hash !! {};

	$!lock.protect: {
		$!era = 'modern';
		$!negotiated-version = $version;
		# A server that never sent us a list has still told us it speaks the
		# version we settled on, which is the only honest thing to report.
		@!supported-versions = @supported.elems ?? @supported.map(*.Str) !! ($version,);
		%!discovery = %result.Hash;
		%!capabilities = %result<capabilities> ~~ Associative ?? %result<capabilities>.Hash !! {};
		%!server-info = %meta{META-SERVER-INFO} ~~ Associative
			?? %meta{META-SERVER-INFO}.Hash !! {};
		$!instructions = %result<instructions> ~~ Str:D ?? %result<instructions> !! Str;
	}
}

method !legacy-handshake(--> Nil) {
	my %result = self!send(
		'initialize',
		{
			protocolVersion => LEGACY-PROTOCOL-VERSION,
			capabilities    => %!declared-capabilities.Hash,
			clientInfo      => self!client-info,
		},
		era => 'legacy', timeout => $!request-timeout,
	);

	# "If the client does not support the version in the server's response, it
	# SHOULD disconnect" -- and 2025-11-25 is the only legacy revision this
	# client implements, so anything else is the end of the conversation.
	my $version = %result<protocolVersion>;
	unless $version ~~ Str:D && $version eq LEGACY-PROTOCOL-VERSION {
		die X::MCP::Client::UnsupportedVersion.new(
			requested => LEGACY-PROTOCOL-VERSION,
			supported => ($version ~~ Str:D ?? ($version,) !! ()),
		);
	}

	$!lock.protect: {
		$!era = 'legacy';
		$!negotiated-version = LEGACY-PROTOCOL-VERSION;
		@!supported-versions = ();
		%!discovery = %result.Hash;
		%!capabilities = %result<capabilities> ~~ Associative ?? %result<capabilities>.Hash !! {};
		%!server-info = %result<serverInfo> ~~ Associative ?? %result<serverInfo>.Hash !! {};
		$!instructions = %result<instructions> ~~ Str:D ?? %result<instructions> !! Str;
	}

	# The handshake is not complete until the server has been told the client
	# is ready; a legacy server may withhold requests other than ping until it
	# arrives.
	$!transport.notify(notification('notifications/initialized'));
}

# Which optional client features we admit to. A server MUST NOT ask for input
# the client has not declared, so this is the switch that decides whether the
# multi round-trip loop can ever be entered at all -- and it is derived from
# the hooks rather than configured, so "I declared elicitation but wired no
# handler" cannot happen.
#
# Shapes verified 2026-08-08 against ClientCapabilities in
# https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts
# (roots: {}, sampling: { context?, tools? }, elicitation: { form?, url? }).
# Elicitation is declared form-mode only: URL mode requires the client to open
# a browser, which a callback returning an ElicitResult cannot be assumed to
# do. Pass %.client-capabilities to say otherwise.
#
# The same hash serves the legacy `initialize` capabilities, whose keys are the
# same three (2025-11-25 lifecycle) -- roots there may carry listChanged, which
# this client does not implement and therefore does not claim.
method !derive-capabilities(--> Hash:D) {
	my %caps;
	%caps<elicitation> = { form => {} } if &!on-elicit.defined;
	%caps<sampling> = {} if &!on-sample.defined;
	%caps<roots> = {} if &!on-list-roots.defined;
	%caps;
}

method !client-info(--> Hash:D) {
	{ name => $!client-name, version => $!client-version };
}

# === Typed API ===

#| The server's tools, each a hash with C<name>, C<description> and
#| C<inputSchema>. Cached for as long as a modern server permits; C<:refresh>
#| forces a re-fetch and drops the cached copy.
method list-tools(Bool :$refresh = False, Real :$timeout --> List:D) {
	self!listing('tools/list', 'tools', :$refresh, :$timeout);
}

#| Call a tool and return its result — normally C<< { content => [...] } >>, plus
#| C<isError> when the tool reported failure. A tool that fails is not an
#| exception: C<isError> is a result, and callers feeding an LLM want the text.
#|
#| Multi round-trips are handled transparently: if the server needs input
#| first, the hooks are consulted and the call is retried until it completes or
#| the round budget runs out.
#|
#| C<:$progress-token> asks the server to report progress on this call, which it
#| does by sending C<notifications/progress> quoting the token back. The
#| notifications arrive on C<notifications> like any other; correlating them
#| with the call is what the token is for, and the token is yours to choose. A
#| server is never obliged to report anything, and one that reports after the
#| call has answered is not misbehaving either — the retries of a multi
#| round-trip call all carry the same token.
method call-tool(
	Str:D $name, %arguments = {},
	Real :$timeout, Promise :$cancelled, Str :$progress-token
	--> Hash:D
) {
	self!ensure-era;
	my %params = name => $name, arguments => %arguments.Hash;
	# Into the parameters' own _meta rather than through a stamp of its own:
	# build-request keeps whatever _meta the caller put there and adds the
	# protocol keys beside it. Both eras spell progressToken the same way — it
	# predates the 2026-07-28 namespacing — so this reaches a legacy server too.
	%params<_meta> = %( (META-PROGRESS-TOKEN) => $progress-token )
		if $progress-token.defined && $progress-token.chars;
	strip-envelope(self!request-with-input('tools/call', %params, :$timeout, :$cancelled));
}

#| The server's resources, each a hash with C<uri>, C<name> and friends.
method list-resources(Bool :$refresh = False, Real :$timeout --> List:D) {
	self!listing('resources/list', 'resources', :$refresh, :$timeout);
}

#| Read one resource by URI, returning C<< { contents => [...] } >>. Cached when
#| the server says it may be — which for a resource whose content it cannot
#| vouch for is never.
method read-resource(
	Str:D $uri, Bool :$refresh = False, Real :$timeout, Promise :$cancelled --> Hash:D
) {
	self!ensure-era;
	my %params = uri => $uri;
	my $key = $!cache.key-for('resources/read', %params);

	my $hit = $!cache.get($key, :$refresh);
	return strip-envelope($hit.Hash) with $hit;

	my %result = self!request-with-input('resources/read', %params, :$timeout, :$cancelled);
	$!cache.put($key, %result, era => self!era-now);
	strip-envelope(%result);
}

#| The server's prompt templates, each a hash with C<name>, C<description> and
#| C<arguments>.
method list-prompts(Bool :$refresh = False, Real :$timeout --> List:D) {
	self!listing('prompts/list', 'prompts', :$refresh, :$timeout);
}

#| Render one prompt template, returning C<< { messages => [...] } >> and usually a
#| C<description>. Arguments are strings by protocol.
method get-prompt(
	Str:D $name, %arguments = {}, Real :$timeout, Promise :$cancelled --> Hash:D
) {
	self!ensure-era;
	my %params = name => $name;
	%params<arguments> = %arguments.Hash if %arguments.elems;
	strip-envelope(self!request-with-input('prompts/get', %params, :$timeout, :$cancelled));
}

#| Ask the server whether it is still there. True when it answered, False when
#| it does not implement C<ping> at all: 2026-07-28 removed the utility, so a
#| strictly modern server answering "no such method" here is healthy rather
#| than broken, and a Bool says so without the caller having to know that. Any
#| other failure is raised. A legacy server always answers.
method ping(Real :$timeout --> Bool:D) {
	self!ensure-era;
	my Bool $answered = True;
	{
		CATCH {
			when X::MCP::Client::Protocol {
				.rethrow unless (.code // 0) == METHOD_NOT_FOUND;
				$answered = False;
			}
		}
		self!request-simple('ping', {}, :$timeout);
	}
	$answered;
}

#| Every notification the server sends, as a live Supply of the parsed message
#| (C<method>, C<params>). Taps see nothing that arrived before they tapped.
method notifications(--> Supply:D) {
	$!notifications.Supply;
}

#| True until C<close>.
method alive(--> Bool:D) {
	($!lock.protect: { !$!closed }) && $!transport.alive;
}

#| Shut the connection down: close the transport, fail anything outstanding,
#| drop the cache and finish the notification Supply. Idempotent, and safe to
#| call on a connection that has already died.
method close(--> Nil) {
	my $already = $!lock.protect: {
		my $was = $!closed;
		$!closed = True;
		$was;
	};
	return if $already;

	$!cache.clear;
	{
		CATCH { default { self!warn('transport close failed: ' ~ .message.lines.head) } }
		$!transport.close;
	}
	$!notifications.done;
}

# === LLM tool bridge ===
#
# Byte-compatible with MCP::Server's bridge (MCP-Server/lib/MCP/Server.rakumod,
# "LLM tool bridge"): the same toolkit behind this client and behind a local
# server must produce the same declarations and the same results, or swapping a
# local toolkit for a remote one would change what the model sees. t/13 pins
# that parity against a live server.

#| The server's tools as OpenAI-style function declarations, ready to hand to
#| C<LLM::Chat::ToolLoop> (or any backend that speaks the same shape):
#| C<< { type => 'function', function => { name, description, parameters } } >>.
#|
#| Built from the cached catalogue, so calling it per request is cheap. The
#| C<parameters> schema is the server's C<inputSchema> verbatim — shared with
#| the cache, and to be treated as read-only. A tool the server declared without
#| a schema gets an empty object schema rather than none, since a function
#| declaration without C<parameters> is invalid to most APIs.
method tools-for-llm(--> List) {
	self.list-tools.map(-> $tool {
		my %tool = $tool ~~ Associative ?? $tool.Hash !! {};
		my $description = %tool<description>;
		{
			type => 'function',
			function => {
				name => (%tool<name> // '').Str,
				|($description.defined ?? (description => $description) !! ()),
				parameters => (%tool<inputSchema> ~~ Associative
					?? %tool<inputSchema>.Hash
					!! { type => 'object', properties => {} }),
			},
		}
	}).list;
}

#| Run the tool calls a model asked for and return one result each, in the same
#| order: C<< { role => 'tool', tool_call_id, content, is_error } >>.
#|
#| Each call is C<< { id, function => { name, arguments } } >>, with C<arguments>
#| either a hash or the JSON string most APIs actually send. Both are accepted,
#| as is the empty string models send for a tool that takes no arguments.
#|
#| B<This never throws.> Every way a call can fail — a malformed entry,
#| arguments that are not a JSON object, a tool this server does not have, a
#| tool that reported C<isError>, a timeout, a server that died, a multi
#| round-trip loop that never converged — comes back as an entry with
#| C<is_error> set and the reason in C<content>.
#|
#| The calls run B<here>, before this returns: the results are a real List and
#| not a lazy sequence a caller might reify somewhere else, or after cancelling
#| the run they belonged to, or never.
#|
#| With C<:&on-progress> wired, each call carries a progress token of its own
#| and the server's reports on it reach that hook tagged with the call's id.
method execute-tool-calls(@tool-calls --> List) {
	# Fetched once for the whole batch: an unknown tool is answered here rather
	# than by the server, which saves a round trip and — because the server's
	# own bridge answers it the same way — keeps the two in step. A catalogue we
	# could not fetch (closed connection, dead server) means no name can be
	# ruled out, so the call goes out and fails on its own merits.
	my $known = self!known-tool-names;

	# Assigned to an array rather than returned as a `.map(...).list`: a Seq's
	# .list is still lazy, so the calls would go out at whatever point the caller
	# first looked at the answers — on another thread, after the run they belong
	# to was cancelled, or never at all. Tools have side effects. They run here,
	# inside the method that was asked to run them, and by the time this returns
	# every one of them has finished. MCP::Server's bridge is eager for the same
	# reason, and t/13 pins the two together.
	my @results = @tool-calls.map(-> $call { self!execute-one($call, $known) });

	@results.List;
}

method !known-tool-names(--> Any) {
	my $names = Nil;
	{
		CATCH { default { $names = Nil } }
		$names = self.list-tools
			.map({ $_ ~~ Associative ?? ($_<name> // '').Str !! '' })
			.Set;
	}
	$names;
}

method !execute-one($call, $known --> Hash:D) {
	# Not an object at all: there is no id to answer with and no name to call,
	# so the only useful thing left is to say so where the model can read it.
	return {
		role => 'tool', tool_call_id => '',
		content => 'Malformed tool call: expected an object with an id and a function',
		is_error => True,
	} unless $call ~~ Associative;

	my %tc = $call.Hash;
	my $function = %tc<function>;
	my $fn-name = ($function ~~ Associative ?? ($function<name> // '') !! '').Str;
	my $args = ($function ~~ Associative ?? $function<arguments> !! Any) // {};
	my $call-id = %tc<id> // '';

	my %arguments;
	my $content;
	my Bool $is-error = False;

	if $args ~~ Associative {
		%arguments = $args.Hash;
	}
	elsif $args.Str.trim eq '' {
		# Models routinely send "" as the arguments of a tool that takes none.
		# That is a call with no arguments, not a broken one, so it runs with the
		# empty %arguments already declared above rather than coming back as a
		# parse error the model cannot act on. The local bridge (MCP::Server's
		# execute-tool-calls) says exactly the same.
	}
	else {
		try {
			my $parsed = from-json($args.Str);
			if $parsed ~~ Associative {
				%arguments = $parsed.Hash;
			}
			else {
				$content = 'Tool arguments must be a JSON object';
				$is-error = True;
			}
			CATCH {
				default {
					$content = "Invalid tool arguments JSON: {.message}";
					$is-error = True;
				}
			}
		}
	}

	if !$is-error {
		if $known.defined && !$known{$fn-name} {
			$content = "Unknown tool: '$fn-name'";
			$is-error = True;
		}
		else {
			try {
				my %result = self!call-with-progress($fn-name, %arguments, $call-id);
				$content = result-to-text(%result);
				# isError is a *result*, not a failure: the text is what the
				# model needs in order to try something else.
				$is-error = ?%result<isError>;
				CATCH {
					default {
						$content = .message;
						$is-error = True;
					}
				}
			}
		}
	}

	{
		role => 'tool',
		tool_call_id => $call-id,
		content => ~($content // ''),
		is_error => $is-error,
	};
}

# One tool call, with a progress token minted for exactly as long as the call is
# in flight, so a notifications/progress can be attributed to the call the model
# made. The registration is dropped on the way out however the call ends —
# answered, failed, timed out, thrown — because a token that outlived its call
# would put a late notification on a tool that has already been answered.
method !call-with-progress($name, %arguments, $call-id --> Hash:D) {
	my $token = self!register-progress($call-id);
	LEAVE self!unregister-progress($token);

	self.call-tool(
		$name, %arguments,
		|($token.defined ?? (progress-token => $token) !! ()),
	);
}

# The token for one bridge call, or an undefined Str when nobody is listening.
# Wiring &.on-progress is what asks a server for progress: reporting it is work
# the server does on our behalf, and asking for notifications that would be
# dropped on arrival is asking for nothing useful. The same rule the client's
# capabilities follow -- the hooks are the declaration.
method !register-progress($call-id --> Str) {
	return Str without &!on-progress;

	$!progress-lock.protect: {
		# A counter, because a retry of the same tool call must not reuse the
		# token of the attempt before it -- which is exactly what using the call
		# id as the token would do -- plus 64 bits of randomness, so a server
		# cannot attach progress to a call it is not serving by guessing at what
		# we minted.
		my $token = 'prog-' ~ ++$!next-progress ~ '-'
			~ (^2).map({ (2 ** 32).rand.Int.fmt('%08x') }).join;
		%!progress-calls{$token} = ~($call-id // '');
		$token;
	}
}

method !unregister-progress(Str $token --> Nil) {
	return without $token;
	$!progress-lock.protect: { %!progress-calls{$token}:delete };
}

# A tool result rendered as the string a model reads. The local bridge has it
# easy -- a toolkit handler returns a string -- but over the wire the same
# answer arrives as content blocks, so this is where the two paths converge.
my sub result-to-text(%result --> Str:D) {
	my $content = %result<content>;

	unless $content ~~ Positional {
		# No content array: an empty result says nothing, and anything else
		# (structuredContent, a server with ideas of its own) is more use to a
		# model as JSON than as silence.
		return '' unless %result.elems;
		return to-json(%result, :!pretty, :sorted-keys);
	}

	$content.list.map(&block-to-text).join("\n");
}

# One content block. Binary payloads are named rather than inlined: a
# base64-encoded PNG in a transcript costs a fortune in tokens and tells the
# model nothing it can act on.
my sub block-to-text($block --> Str:D) {
	return ~($block // '') unless $block ~~ Associative;

	my %block = $block.Hash;
	my $type = %block<type> ~~ Str:D ?? %block<type> !! '';

	given $type {
		when 'text' {
			~(%block<text> // '');
		}
		when 'image' | 'audio' {
			"[$type: {(%block<mimeType> // 'unknown media type').Str}]";
		}
		when 'resource' {
			my %embedded = %block<resource> ~~ Associative ?? %block<resource>.Hash !! {};
			%embedded<text> ~~ Str:D
				?? %embedded<text>
				!! "[resource: {(%embedded<uri> // 'unknown').Str}]";
		}
		when 'resource_link' {
			"[resource: {(%block<uri> // 'unknown').Str}]";
		}
		default {
			to-json(%block, :!pretty, :sorted-keys);
		}
	}
}

# === Async twins ===
#
# Every one of these is the blocking method on a thread-pool thread. The
# transports multiplex and correlation is by id, so several may be in flight at
# once; the era probe is serialised behind its own lock, so a burst of first
# calls produces one probe and the rest wait for it.

#| Promise twin of C<era>.
method era-async(--> Promise:D) { start { self.era } }
#| Promise twin of C<discover>.
method discover-async(--> Promise:D) { start { self.discover } }
#| Promise twin of C<server-info>.
method server-info-async(--> Promise:D) { start { self.server-info } }
#| Promise twin of C<capabilities>.
method capabilities-async(--> Promise:D) { start { self.capabilities } }
#| Promise twin of C<instructions>.
method instructions-async(--> Promise:D) { start { self.instructions } }
#| Promise twin of C<list-tools>.
method list-tools-async(|args --> Promise:D) { start { self.list-tools(|args) } }
#| Promise twin of C<call-tool>.
method call-tool-async(|args --> Promise:D) { start { self.call-tool(|args) } }
#| Promise twin of C<list-resources>.
method list-resources-async(|args --> Promise:D) { start { self.list-resources(|args) } }
#| Promise twin of C<read-resource>.
method read-resource-async(|args --> Promise:D) { start { self.read-resource(|args) } }
#| Promise twin of C<list-prompts>.
method list-prompts-async(|args --> Promise:D) { start { self.list-prompts(|args) } }
#| Promise twin of C<get-prompt>.
method get-prompt-async(|args --> Promise:D) { start { self.get-prompt(|args) } }
#| Promise twin of C<ping>.
method ping-async(|args --> Promise:D) { start { self.ping(|args) } }

# === Requests ===

# The three cacheable catalog listings, which differ only in their method name
# and the key the array hides under.
method !listing(Str:D $method, Str:D $key, Bool :$refresh, Real :$timeout --> List:D) {
	self!ensure-era;
	my $cache-key = $!cache.key-for($method);

	my $hit = $!cache.get($cache-key, :$refresh);
	without $hit {
		my %result = self!request-simple($method, {}, :$timeout);
		$!cache.put($cache-key, %result, era => self!era-now);
		$hit = %result;
	}

	$hit{$key} ~~ Positional ?? $hit{$key}.list !! ();
}

# One request, one answer, no round trips. Any input_required here is a
# protocol violation: the spec names exactly three methods a server may ask for
# input on, and this is not how any of them get sent.
method !request-simple(Str:D $method, %params, Real :$timeout, Promise :$cancelled --> Hash:D) {
	my %result = self!send($method, %params, :$timeout, :$cancelled);
	my $type = %result<resultType> // RESULT-TYPE-COMPLETE;

	if $type eq RESULT-TYPE-INPUT-REQUIRED {
		die X::MCP::Client::Protocol.new(
			detail => "server asked for input on '$method', which the 2026-07-28 "
				~ 'specification does not allow (only '
				~ MRTR-METHODS.keys.sort.join(', ') ~ ' may return input_required)',
		);
	}
	die X::MCP::Client::Protocol.new(
		detail => "server answered '$method' with an unrecognised resultType '$type'",
	) unless $type eq RESULT-TYPE-COMPLETE;

	%result;
}

# The multi round-trip loop.
#
# Verified 2026-08-08 against
# https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr
# and the schema at
# https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts:
#
#   * InputRequests is a *map*, not an array: keys are server-assigned string
#     ids unique within the request, values are ElicitRequest /
#     CreateMessageRequest / ListRootsRequest objects ({ method, params }).
#   * InputResponses is a map with the *same keys*, values are the bare client
#     results (ElicitResult / CreateMessageResult / ListRootsResult). There is
#     no id member and no error member anywhere in it.
#   * inputResponses and requestState both sit at the top level of the retry's
#     params, alongside name/arguments/uri (InputResponseRequestParams).
#   * requestState is opaque: "Clients MUST NOT inspect, parse, modify, or make
#     any assumptions about its contents", and MUST be echoed back exactly. If
#     the server sent none, the client MUST NOT invent one.
#   * "The JSON-RPC id MUST be different between the initial request and the
#     retry, as they are independent requests" -- !send takes a fresh id every
#     time it is called, so each round is a new id by construction.
#   * A result with inputRequests absent MAY be retried immediately; a server
#     MUST include at least one of inputRequests and requestState, so neither
#     is a protocol violation and not an invitation to spin.
method !request-with-input(
	Str:D $method, %params, Real :$timeout, Promise :$cancelled --> Hash:D
) {
	die X::MCP::Client.new(detail => "'$method' is not a multi round-trip method")
		unless MRTR-METHODS{$method};

	# Every retry is built from the original parameters rather than from the
	# previous retry: the server reconstitutes its context from requestState,
	# and accumulating stale inputResponses across rounds would answer
	# questions that are no longer being asked.
	my %send = %params.Hash;
	my UInt $round = 0;

	loop {
		my %result = self!send($method, %send, :$timeout, :$cancelled);
		my $type = %result<resultType> // RESULT-TYPE-COMPLETE;

		return %result if $type eq RESULT-TYPE-COMPLETE;
		die X::MCP::Client::Protocol.new(
			detail => "server answered '$method' with an unrecognised resultType '$type'",
		) unless $type eq RESULT-TYPE-INPUT-REQUIRED;

		my $requests = %result<inputRequests>;
		my $state = %result<requestState>;
		my $has-requests = $requests ~~ Associative && $requests.elems > 0;
		my $has-state = $state ~~ Str:D;

		die X::MCP::Client::Protocol.new(
			detail => "server asked for input on '$method' but sent neither "
				~ 'inputRequests nor requestState, so there is nothing to retry with',
		) unless $has-requests || $has-state;

		die X::MCP::Client::InputLoopExceeded.new(
			rounds => $!max-input-rounds, :$method,
		) if $round >= $!max-input-rounds;
		++$round;

		%send = %params.Hash;
		if $has-requests {
			my %responses = self!fulfil-inputs($requests);
			%send<inputResponses> = %responses if %responses.elems;
		}
		%send<requestState> = $state if $has-state;
	}
}

# Turn one inputRequests map into one inputResponses map. Keys are copied
# across untouched -- they are the server's, and the only thing tying an answer
# to its question.
method !fulfil-inputs($requests --> Hash:D) {
	my %responses;
	return %responses unless $requests ~~ Associative;

	for $requests.Hash.kv -> $key, $request {
		my %req = $request ~~ Associative ?? $request.Hash !! {};
		my $body = self!fulfil-one($key, %req);
		# An undefined body means "no answer we can honestly give": the key is
		# left out entirely, which the spec handles (the server SHOULD ask
		# again) and the round budget bounds.
		%responses{$key} = $body.Hash with $body;
	}

	%responses;
}

method !fulfil-one(Str:D $key, %req --> Hash) {
	my $method = %req<method> ~~ Str:D ?? %req<method> !! '';

	my &hook = do given $method {
		when 'elicitation/create'     { &!on-elicit }
		when 'sampling/createMessage' { &!on-sample }
		when 'roots/list'             { &!on-list-roots }
		default                       { Callable }
	};

	# No hook is not an error: it is a refusal, and one the server should never
	# have provoked, because a capability it was never told about is a
	# capability it must not ask for.
	return decline-input-response(%req) without &hook;

	my $body;
	{
		CATCH {
			default {
				self!warn(
					"the hook for '$method' (input '$key') threw, declining: "
						~ .message.lines.head
				);
				$body = Nil;
			}
		}
		$body = &hook(%req);
	}

	return decline-input-response(%req) unless $body ~~ Associative;
	$body.Hash;
}

# Build, send and await one request. The single place a JSON-RPC id is minted,
# which is what makes "a new id per round" true by construction rather than by
# discipline.
method !send(
	Str:D $method, %params,
	Str :$era, Str :$protocol-version, Real :$timeout, Promise :$cancelled
	--> Hash:D
) {
	self!check-open;

	my $use-era = $era // self!era-now;
	my $id = $!lock.protect: { ++$!next-id };

	# Collected into a hash rather than slipped in as a list of pairs: `|` on a
	# list of Pairs flattens them as *positionals*, and build-request would be
	# handed six positional arguments instead of three named ones.
	my %stamps;
	if $use-era eq 'modern' {
		%stamps<protocol-version> = $protocol-version // $!negotiated-version
			// @!protocol-versions[0];
		%stamps<client-info> = self!client-info;
		%stamps<client-capabilities> = %!declared-capabilities.Hash;
		%stamps<log-level> = $!log-level if $!log-level.defined;
	}

	my %msg = build-request($id, $method, %params, era => $use-era, |%stamps);

	my $answer = $!transport.request(
		%msg,
		on-notification => &!notification-sink,
		|($cancelled.defined ?? (:$cancelled) !! ()),
		timeout => ($timeout // $!request-timeout),
	);

	my $result = await $answer;
	normalize-result($result);
}

method !era-now(--> Str:D) {
	($!lock.protect: { $!era }) // 'modern';
}

method !check-open(--> Nil) {
	die X::MCP::Client::TransportClosed.new(detail => 'this client has been closed')
		if $!lock.protect: { $!closed };
}

method !receive-notification(%note --> Nil) {
	{
		CATCH { default { self!warn('notification subscriber failed: ' ~ .message.lines.head) } }
		$!notifications.emit(%note);
	}

	my $method = %note<method> ~~ Str:D ?? %note<method> !! '';
	my %params = %note<params> ~~ Associative ?? %note<params>.Hash !! {};

	if $method eq 'notifications/progress' {
		self!deliver-progress(%params);
		return;
	}

	return without &!on-log;
	return unless $method eq 'notifications/message';

	CATCH { default { self!warn('on-log hook threw: ' ~ .message.lines.head) } }
	&!on-log(%params);
}

# One notifications/progress, turned into the payload &.on-progress is
# documented to take. Everything about it is best-effort: this runs on the
# reader thread, in front of every answer still on the wire, and there is
# nothing a malformed progress report is worth interrupting.
method !deliver-progress(%params --> Nil) {
	return without &!on-progress;

	# Spelled out rather than taken from META-PROGRESS-TOKEN: that constant names
	# the key inside a request's _meta, and this is a top-level member of
	# ProgressNotificationParams. The two strings agree, the two fields do not.
	my $token = %params<progressToken>;
	return unless $token.defined;

	# An unknown token is a report for a call that has already been answered, or
	# one this client never made. Neither has an operation to attribute it to, so
	# it is dropped in silence rather than guessed at or warned about -- a server
	# racing its own answer is normal, not a fault.
	my $call-id = $!progress-lock.protect: { %!progress-calls{$token.Str} };
	return without $call-id;

	# progress is the one member ProgressNotificationParams requires besides the
	# token, and it is a number. Without it there is nothing to report.
	my $progress = %params<progress>;
	return unless $progress ~~ Real:D && $progress !~~ Bool;

	my %payload = tool-call-id => $call-id, progress => $progress.Num;
	%payload<total> = %params<total>.Num
		if %params<total> ~~ Real:D && %params<total> !~~ Bool;
	%payload<message> = %params<message> if %params<message> ~~ Str:D;

	CATCH { default { self!warn('on-progress hook threw: ' ~ .message.lines.head) } }
	&!on-progress(%payload);
}

method !warn(Str:D $message --> Nil) {
	return without &!on-warn;
	CATCH { default { } }   # a warning hook that throws is not worth a crash
	&!on-warn($message);
}

# Protocol bookkeeping a caller of the typed API has no use for. Not a deep
# copy: the nested content is the caller's to read, and copying a resource read
# on the way out of the cache would cost more than the cache saves.
my sub strip-envelope(%result --> Hash:D) {
	my %out = %result.Hash;
	%out{$_}:delete for ENVELOPE-KEYS;
	%out;
}
