[![Actions Status](https://github.com/m-doughty/MCP-Client/actions/workflows/test.yml/badge.svg)](https://github.com/m-doughty/MCP-Client/actions)

MCP::Client
===========

A client for [Model Context Protocol](https://modelcontextprotocol.io) servers. Connect to a third-party MCP server over stdio or Streamable HTTP, call its tools, read its resources, render its prompts — and hand the whole catalogue to an LLM tool loop as if it were a local toolkit.

Both protocol eras are spoken: the `2025-11-25` handshake era and the stateless `2026-07-28` era. Which one a server wants is worked out by probing it, once, on the first call that needs to know.

Synopsis
--------

```raku
use MCP::Client;
use MCP::Client::Registry;
use LLM::Chat::ToolLoop;

my $mcp = MCP::Client.connect-stdio(
    command     => 'mcp-server-filesystem',
    args        => ['/srv/docs'],
    client-name => 'my-agent',
);

say $mcp.era;                 # modern | legacy -- probed on first use
say $mcp.server-info<name>;

for $mcp.list-tools -> %tool {
    say "%tool<name>: %tool<description>";
}

my %result = $mcp.call-tool('read_file', { path => '/srv/docs/README' });
say .<text> for %result<content>.grep({ .<type> eq 'text' });

# The same server, as tools for a model. A local MCP::Server toolkit would
# be added the same way, under its own prefix.
my $tools = MCP::Client::Registry.new;
$tools.add($mcp, prefix => 'fs');

my $loop = LLM::Chat::ToolLoop.new(
    :$backend,
    tools         => $tools.tools-for-llm,
    execute-tools => -> @calls { $tools.execute-tool-calls(@calls) },
);

$mcp.close;
```

Description
-----------

MCP::Client has one job: make a third-party MCP server usable from Raku without the caller having to care which revision of the protocol that server speaks, whether it wants a handshake, whether its answers may be cached, or whether it will interrupt a tool call to ask a question.

The distribution is a handful of units with clean seams, each carrying its own Pod6:

  * [MCP::Client](lib/MCP/Client.rakumod) — the client class: connection, era negotiation, the typed API, the multi round-trip loop, the LLM bridge.

  * [MCP::Client::Registry](lib/MCP/Client/Registry.rakumod) — one prefixed tool namespace over many providers, remote and local.

  * [MCP::Client::Transport](lib/MCP/Client/Transport.rakumod) — the role a wire implements, and the contract it signs up to.

  * [MCP::Client::Transport::Stdio](lib/MCP/Client/Transport/Stdio.rakumod) — a server run as a child process.

  * [MCP::Client::Transport::HTTP](lib/MCP/Client/Transport/HTTP.rakumod) — the 2026-07-28 Streamable HTTP transport.

  * [MCP::Client::Exceptions](lib/MCP/Client/Exceptions.rakumod) — the typed failure vocabulary.

  * [MCP::Client::Protocol](lib/MCP/Client/Protocol.rakumod) — request building, inbound-message classification, result shaping.

  * [MCP::Client::Correlator](lib/MCP/Client/Correlator.rakumod) — the pending-request table that makes one pipe carry many conversations.

  * [MCP::Client::SSE](lib/MCP/Client/SSE.rakumod) — an incremental Server-Sent Events parser.

  * [MCP::Client::Cache](lib/MCP/Client/Cache.rakumod) — the `ttlMs`/`cacheScope` result cache.

Everything on this page is `MCP::Client`'s own API unless it says otherwise.

Protocol eras
-------------

There are two, and they are not compatible.

  * **Legacy** — `2025-11-25` and earlier. Session-shaped: the client opens with `initialize`, the server answers with its version and capabilities, the client sends `notifications/initialized`, and the connection carries that agreement until it hangs up.

  * **Modern** — `2026-07-28`. Stateless: no handshake, no session. Every request carries its own protocol version, client identity and client capabilities in `params._meta`, so any request may be served by any instance of the server, and a result may say how long it can be cached for.

The client decides which it is talking to on the first call that needs the answer and remembers it for the life of the connection, because the era is a property of the server rather than of a request. Nothing has to be configured, and nothing has to be awaited: `era` forces the probe and reports the verdict, but so does the first `list-tools`.

```raku
my $mcp = MCP::Client.connect-stdio(command => 'some-server');

say $mcp.era;                 # 'modern' or 'legacy'
say $mcp.protocol-version;    # '2026-07-28', or '2025-11-25' after a handshake
say $mcp.supported-versions;  # every version the server named (empty for legacy)
say $mcp.server-info<name>;
say $mcp.capabilities.keys;   # tools resources prompts ...
say $mcp.instructions;        # the server's advice to a model, or Str
```

### The probe

One request, under a short budget of its own (`:$probe-timeout`, five seconds by default, deliberately separate from `:$request-timeout` — a legacy server does not answer `server/discover` at all, and waiting a full minute to discover that would make every connection to one feel broken):

  * A `DiscoverResult` whose `supportedVersions` overlaps ours ⇒ **modern**, at the first version *we* prefer that the server also named. Preference is the client's, not the server's.

  * `-32022 UnsupportedProtocolVersion` ⇒ the server is certainly modern, since only a modern server emits that code. If its `data.supported` names another version we speak, the probe is repeated at that version; if it names only `2025-11-25`, the client falls back to the handshake; if it names nothing we can use, `X::MCP::Client::UnsupportedVersion`.

  * `-32020` or `-32021` ⇒ modern, but the server told us nothing about itself. The catalogue calls will fill that in.

  * Anything else — `-32601 method not found`, a parse error, a timeout, a reply that is not a `DiscoverResult` — ⇒ **legacy**: `initialize`, check the version that came back, then `notifications/initialized`.

An empty `supportedVersions` falls in that last group on purpose. It is what `MCP::Server` answers when it is configured for the legacy era only, and it means the same thing as a disjoint list: the server has declined to offer a modern version, so ask it the old way.

**A dead wire is not an era signal.** If the probe fails because the server process is gone, the connection was closed, or the caller cancelled, that failure is raised rather than misread as "must be an old server" — replacing "the server exited with code 127" with a second, more confusing failure helps nobody.

### Pinning a version

`:@protocol-versions` is the list of **modern** versions this client will speak, best first. The legacy era is always available as a fallback and must not appear in it: legacy is reached by handshake, not by version stamp, so naming it is a mistake the constructor refuses rather than honours.

```raku
# Speak only 2026-07-28, and fall back to the handshake for anything older.
MCP::Client.connect-stdio(
    command           => 'srv',
    protocol-versions => ['2026-07-28',],
);

MCP::Client.connect-stdio(command => 'srv', protocol-versions => ['2025-11-25',]);
# dies: X::MCP::Client::UnsupportedVersion
```

Connecting
----------

### stdio

The transport almost every MCP server in the wild speaks: the server is a child process, one JSON-RPC message per line each way, stderr is a log nobody was supposed to have to read until something went wrong.

```raku
my $mcp = MCP::Client.connect-stdio(
    command   => 'mcp-server-git',
    args      => ['--repository', '/srv/project'],
    env       => { GIT_AUTHOR_NAME => 'agent' },
    cwd       => '/srv/project',
    on-stderr => -> Str:D $line { note "[git-server] $line" },
);
```

`$command` is executed directly through `Proc::Async`. **There is no shell** — nothing reaches `sh` or `cmd.exe` — so there is no quoting to get wrong, no glob expansion, no `$(...)`, and no injection: an argument containing `; rm -rf /` is one argument containing that text. Two consequences are worth knowing before a Windows user files a bug:

  * **No `PATH` extension magic on Windows.** `$command` must name a file that exists — `npx.cmd`, not `npx`. And since a `.cmd` is a batch script rather than an executable, Windows can only run it through `cmd.exe`: name a real `.exe` where there is one, or ask for the interpreter explicitly and accept its quoting rules.

  * **NUL bytes are refused.** A `\0` in the command, an argument or an environment entry cannot survive the syscall boundary intact, so it is rejected up front with `X::MCP::Client::SpawnFailed` rather than silently truncating what the child receives.

```raku
# The npm-shipped servers are launched through npx, which on Windows is a
# batch shim. Nothing here supplies a shell, so ask for one by name.
my ($command, @shim) = $*DISTRO.is-win
    ?? ('cmd.exe', ['/c', 'npx'])
    !! ('npx',     []);

my $mcp = MCP::Client.connect-stdio(
    :$command,
    args => [|@shim, '-y', '@modelcontextprotocol/server-filesystem', '/srv/docs'],
);
```

The child inherits this process's environment by default and `%env` is layered on top of it, because a server that cannot see `PATH` or `HOME` usually cannot start. `:!inherit-env` gives it `%env` and nothing else.

### Streamable HTTP

```raku
my $mcp = MCP::Client.connect-http(
    url     => 'https://tools.example.com/mcp',
    headers => { Authorization => 'Bearer ' ~ %*ENV<TOOLS_TOKEN> },
);
```

**Modern era only.** There is no `initialize` handshake over HTTP here, so a server that speaks only `2025-11-25` over HTTP cannot be talked to (see [Limitations](#limitations)). The Cro dependency this transport needs is loaded on demand — a stdio client never pays for it at startup.

Each JSON-RPC message is its own POST, and a handful of its fields are mirrored into headers so that gateways can route without parsing bodies: `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` for the three methods that name a thing. The `x-mcp-header` annotation feature is implemented in full, transparently — see [MCP::Client::Transport::HTTP](lib/MCP/Client/Transport/HTTP.rakumod).

### Options

Both `connect-*` methods take every option `MCP::Client.new` does, and pass the transport's own knobs through to the transport they build:

<table class="pod-table">
<thead><tr>
<th>Option</th> <th>Default</th> <th>What it does</th>
</tr></thead>
<tbody>
<tr> <td>client-name</td> <td>raku-mcp-client</td> <td>Reported to the server as clientInfo; diagnostics only</td> </tr> <tr> <td>client-version</td> <td>0.1.0</td> <td>Ditto</td> </tr> <tr> <td>protocol-versions</td> <td>(2026-07-28,)</td> <td>Modern versions to offer, best first</td> </tr> <tr> <td>request-timeout</td> <td>60</td> <td>Seconds an ordinary request may take; 0 disables the budget</td> </tr> <tr> <td>probe-timeout</td> <td>5</td> <td>Seconds the era probe may take</td> </tr> <tr> <td>max-input-rounds</td> <td>8</td> <td>Multi round-trip retries before giving up</td> </tr> <tr> <td>on-elicit</td> <td>(unset)</td> <td>Serve elicitation/create; declares the capability</td> </tr> <tr> <td>on-sample</td> <td>(unset)</td> <td>Serve sampling/createMessage; declares the capability</td> </tr> <tr> <td>on-list-roots</td> <td>(unset)</td> <td>Serve roots/list; declares the capability</td> </tr> <tr> <td>on-log</td> <td>(unset)</td> <td>Called with the params of each notifications/message</td> </tr> <tr> <td>on-progress</td> <td>(unset)</td> <td>Called as a bridge tool call reports progress; asks for it too</td> </tr> <tr> <td>on-warn</td> <td>note to $*ERR</td> <td>One-line diagnostics; shared with the transport</td> </tr> <tr> <td>log-level</td> <td>(unset)</td> <td>Ask a modern server for logs at this severity</td> </tr> <tr> <td>client-capabilities</td> <td>derived from hooks</td> <td>Override the derivation</td> </tr> <tr> <td>cache</td> <td>a fresh one</td> <td>Share a cache, or inject one with a virtual clock</td> </tr>
</tbody>
</table>

Stdio also takes `:&on-stderr`, `:$kill-grace`, `:$stderr-lines` and `:$inherit-env`; HTTP also takes `:$http-version`, `:$persistent` and `:$connect-timeout`. Those reach the transport rather than the client. `:&on-warn` is the one option that serves both: the client reports its own papered-over problems through it (an input hook that threw, a notification subscriber that died) and the transport reports wire-level ones (a line of stdout that was not JSON-RPC, a late answer to a request that had already given up).

```raku
my $mcp = MCP::Client.connect-stdio(
    command => 'chatty-server',
    on-warn => -> Str:D $message { $log.warn("mcp: $message") },
);
```

An option neither the client nor its transport recognises is an error, not a shrug — `.new` ignoring an unknown named argument is how a typo in a hook name becomes a client that quietly never elicits:

```raku
MCP::Client.connect-stdio(command => 'srv', on-elicits => &ask);
# dies: X::MCP::Client: unknown option: on-elicits
```

`:$transport` substitutes a ready-made transport for the one `connect-*` would have built — which is how the test suite drives the client with no subprocess anywhere. Transport options are refused in that case rather than silently ignored, since there is nothing left for them to configure.

Calling tools, resources and prompts
------------------------------------

Every method blocks, and every method has an `-async` twin returning a `Promise`.

```raku
my @tools = $mcp.list-tools;         # name, description, inputSchema
my @res   = $mcp.list-resources;     # uri, name, mimeType, ...
my @prompts = $mcp.list-prompts;     # name, description, arguments

my %call   = $mcp.call-tool('search', { query => 'raku' });
my %read   = $mcp.read-resource('file:///srv/docs/README');
my %render = $mcp.get-prompt('review', { code => $source });
```

The three results have three shapes, and the protocol bookkeeping — `resultType`, `_meta`, `ttlMs`, `cacheScope`, `requestState`, `inputRequests` — is stripped before you see it, having already been acted on:

```raku
# call-tool: content blocks, plus isError when the tool reported failure.
%call = {
    content => [ { type => 'text', text => 'three results...' } ],
};

# read-resource: one entry per thing the URI resolved to.
%read = {
    contents => [ { uri => 'file:///srv/docs/README', mimeType => 'text/plain',
                    text => '# Project' } ],
};

# get-prompt: a rendered conversation, ready to prepend to a chat.
%render = {
    description => 'Code review prompt',
    messages    => [ { role => 'user',
                       content => { type => 'text', text => 'Please review...' } } ],
};
```

**A tool that fails is not an exception.** `isError` is part of a perfectly good result, and a caller feeding a model wants the text of it far more than it wants a throw:

```raku
my %result = $mcp.call-tool('deploy', { env => 'prod' });
if %result<isError> {
    note 'the tool refused: ' ~ %result<content>.map({ .<text> // '' }).join;
}
```

### Caching

`tools/list`, `prompts/list`, `resources/list` and `resources/read` are the four results the protocol allows a client to hold on to, and each carries the `ttlMs` the server is prepared to promise. The client honours exactly that: no `ttlMs` (or `ttlMs` of `0`) means no storage, expiry is by the clock, and **a legacy server's answers are never cached**, because the 2025-11-25 era has no cache metadata and nothing legitimises reuse.

That makes `list-tools` cheap enough to call per model turn, which is what an agent loop does.

```raku
my @first  = $mcp.list-tools;            # one round trip
my @cached = $mcp.list-tools;            # no round trip, if the server allowed it

my @fresh  = $mcp.list-tools(:refresh);  # bypass and re-fetch, dropping the entry
```

`:refresh` is on all four. It is what to reach for after a `notifications/tools/list_changed`:

```raku
$mcp.notifications.tap: -> %note {
    $catalogue = $mcp.list-tools(:refresh)
        if %note<method> eq 'notifications/tools/list_changed';
};
```

### Timeouts

`:$request-timeout` is the connection-wide budget (60 seconds); every call may override it. `0` means "no budget", which only makes sense when the caller is managing cancellation itself.

```raku
$mcp.call-tool('reindex', {}, timeout => 600);   # this one is allowed to take ten minutes
```

A timeout is `X::MCP::Client::Timeout`, and **the connection survives it**: the request stops being tracked, a late answer for it is dropped, and the next request goes out normally.

### Cancellation

`:$cancelled` takes a `Promise`. Keeping it abandons the request.

```raku
my $stop = Promise.new;
my $answer = $mcp.call-tool-async('crawl', { url => $url }, cancelled => $stop);

$stop.keep(True) if $user-pressed-escape;
# await $answer now throws X::MCP::Client::Cancelled
```

What the server learns depends on the transport. Over HTTP, closing the response stream **is** the cancellation signal the 2026-07-28 transport defines, so the server sees the hang-up and can stop. Over stdio there is no such signal: the request stops being tracked, the server finishes it anyway, and its answer is dropped when it arrives. Cancelling frees the caller, not the server.

### Async

The twins are the blocking methods on a thread-pool thread. The transports multiplex and correlation is by JSON-RPC id, so several requests may be in flight at once; the era probe is serialised behind its own lock, so a burst of first calls produces one probe and the rest wait for it.

```raku
my @answers = await (
    $mcp.call-tool-async('search', { query => 'raku' }),
    $mcp.call-tool-async('search', { query => 'perl' }),
    $mcp.read-resource-async('file:///srv/docs/README'),
);
```

### Notifications and logging

`notifications` is a live `Supply` of every notification the server sends — progress, log messages, list-changed. Taps see nothing that arrived before they tapped.

```raku
my $mcp = MCP::Client.connect-stdio(
    command   => 'srv',
    log-level => 'info',
    on-log    => -> %params { note "[%params<level>] %params<data>" },
);

$mcp.notifications.tap: -> %note { $ui.progress(%note) };
```

**Set `:$log-level` if you want log notifications from a modern server at all.** 2026-07-28 removed `logging/setLevel` in favour of a per-request `_meta` level, and a server **must not** emit `notifications/message` for a request that did not carry one — so an `on-log` hook without a `log-level` will never fire. On a legacy server the level is a session setting, sent with `logging/setLevel`, which this client leaves to the caller.

### Progress

Progress is opt-in the same way, from this end: a request carries a `progressToken` when the caller wants to be kept posted, and a server must not report on one that did not. `:&on-progress` is both halves of that for the LLM bridge — wiring it is what attaches a token to every tool call the bridge runs, and it is where the reports come back:

```raku
my $mcp = MCP::Client.connect-stdio(
    command     => 'server',
    on-progress => -> %p {
        $ui.progress(%p<tool-call-id>, %p<progress>, %p<total>, %p<message>);
    },
);
```

The payload is `{ tool-call-id, progress, total?, message? } `. `tool-call-id` is the id of the call the model made — the join key back to the tool card it belongs on — and the two optional members are there only when the server sent them. The token itself is minted per call rather than being the call id, which a retried call would reuse, and it is forgotten the moment the call answers: a report that arrives late, or one quoting a token this client did not mint, is dropped rather than attributed to the wrong tool.

Like `on-log`, the hook fires **on the client's reader thread**, ahead of the answer it belongs to. Treat it as a leaf — hand the payload to a queue or a store and return — because work done there delays every message behind it on the connection, and calling back into the client from it deadlocks on the request in flight.

Outside the bridge, `call-tool` takes a `:$progress-token` of your own and the notifications arrive on `notifications` like any other. Both eras spell the token the same way, so a legacy server reports progress too.

### Liveness and shutdown

`ping` is a legacy utility: 2026-07-28 removed it, and a strictly modern server answering "no such method" is healthy rather than broken. The `Bool` says which happened without the caller having to know the history — `True` for an answer, `False` for a server that does not implement it, and any other failure raised.

`close` shuts the connection down: the transport closes (for stdio, stdin is closed, the child is given `:$kill-grace` seconds and then killed), anything outstanding fails with `X::MCP::Client::TransportClosed`, the cache is dropped and the notification Supply finishes. It is idempotent, and safe on a connection whose server died an hour ago.

```raku
my $mcp = MCP::Client.connect-stdio(command => 'srv');
LEAVE $mcp.close;    # the child process is yours to reap
```

Multi round-trip requests
-------------------------

A modern server may answer `tools/call`, `resources/read` or `prompts/get` with `resultType: "input_required"` instead of a result: it needs something from the client — a question answered, an LLM consulted, a root list — before it can finish. The client fulfils those requests and **retries** the original call under a fresh JSON-RPC id, carrying the answers and the server's opaque `requestState` back with it. That is the whole reason the modern protocol can be stateless, and it is handled transparently: `call-tool` returns the final result, however many round trips it took.

Wire a hook for each kind of input you are willing to serve. Each is called with the server's request (`method` and `params`) and returns the body of the matching result:

```raku
my $mcp = MCP::Client.connect-stdio(
    command => 'srv',

    # ElicitRequest -> ElicitResult
    on-elicit => -> %request {
        my %schema = %request<params><requestedSchema>;
        { action => 'accept', content => $ui.ask(%request<params><message>, %schema) };
    },

    # CreateMessageRequest -> CreateMessageResult
    on-sample => -> %request {
        my $text = $my-llm.complete(%request<params><messages>);
        {
            model   => 'my-local-model',
            role    => 'assistant',
            content => { type => 'text', text => $text },
        };
    },

    # ListRootsRequest -> ListRootsResult
    on-list-roots => -> %request {
        { roots => [ { uri => 'file:///srv/project', name => 'project' } ] };
    },
);
```

### Which hooks you set is what you declare

The client's capabilities are **derived from the hooks**, not configured separately, so "I declared elicitation but wired no handler" cannot happen. A server is forbidden from asking for input the client never declared, which makes an unset hook both a refusal and a promise never to be asked:

```raku
MCP::Client.connect-stdio(command => 'srv').declared-capabilities;
# {}

MCP::Client.connect-stdio(command => 'srv', on-elicit => &ask).declared-capabilities;
# { elicitation => { form => {} } }
```

Elicitation is declared form-mode only. URL mode requires the client to open a browser, which a callback returning an `ElicitResult` cannot be assumed to do; `%.client-capabilities` overrides the derivation for a caller who can.

### Declining

Refusal is a first-class answer, not a failure. An unset hook, a hook that throws, or a hook that returns something that is not a hash all decline:

  * **elicitation** — `{ action => 'decline' } `, which is a shape the specification defines and servers are required to handle.

  * **roots** — an empty root list.

  * **sampling** — there is no decline shape for it, so the key is left out of `inputResponses` entirely. The server SHOULD then ask again or give up; either way the round budget bounds it.

A hook that throws is declined and reported through `:&on-warn`, so a bug in a permission dialog degrades to "the server was told no" rather than taking the tool call down with it.

### The round budget

A server that never stops asking cannot pin the client: after `:$max-input-rounds` retries (eight by default) the call fails with `X::MCP::Client::InputLoopExceeded`. Raise it for a server that legitimately conducts a long conversation; lower it to one for a caller that will tolerate exactly one question.

### A permission UI, wired

The realistic shape — every elicitation goes in front of a human, with a remembered allow-list so the same question is not asked twice, and a default of "no" when there is nobody to ask:

```raku
my %remembered;
my $ask-lock = Lock.new;

sub ask-the-user(%request --> Hash) {
    my %params  = %request<params> // {};
    my $message = (%params<message> // 'The server is asking for something.').Str;

    $ask-lock.protect: {
        # Hooks are called on whichever thread the call is running on, and two
        # tools may be in flight at once. One dialog at a time.
        if %remembered{$message}:exists {
            return { action => 'accept', content => %remembered{$message} };
        }

        my $answer = $ui.prompt($message, %params<requestedSchema>);

        # 'decline' answers the question with a no; 'cancel' says the user
        # dismissed the whole request rather than answering it. The server is
        # required to handle both.
        without $answer {
            return { action => 'cancel' };
        }

        %remembered{$message} = $answer if $ui.remember-this;
        return { action => 'accept', content => $answer };
    }
}

my $mcp = MCP::Client.connect-stdio(
    command          => 'srv',
    on-elicit        => &ask-the-user,
    max-input-rounds => 3,
    on-warn          => -> Str:D $m { $log.warn("mcp: $m") },
);

{
    CATCH {
        when X::MCP::Client::InputLoopExceeded {
            note "'{.method}' kept asking past {.rounds} rounds; giving up";
        }
    }
    $mcp.call-tool('deploy', { env => 'prod' });
}
```

Note the `return`s: `&ask-the-user` is a `sub`, so returning from inside the `Lock.protect` block works. Written as a pointy block (`-> %request { ... } `) it would not — a pointy block is a `Block`, not a `Routine`, and `return` from one dies. Use `if`/`with` guards there instead.

The LLM bridge and the Registry
-------------------------------

`tools-for-llm` renders a server's catalogue as OpenAI-style function declarations, and `execute-tool-calls` runs the calls a model asked for. The pair is **byte-compatible with `MCP::Server`'s**, which is the whole point: a toolkit running in this process and a server running on the other side of a pipe are interchangeable to the caller, and a test pins that parity against a live server.

```raku
$mcp.tools-for-llm;
# ({ type => 'function',
#    function => { name => 'read_file', description => 'Read a file',
#                  parameters => { type => 'object', properties => { ... } } } }, ...)

$mcp.execute-tool-calls([
    { id => 'call_1', function => { name => 'read_file',
                                    arguments => '{"path":"/srv/docs/README"}' } },
]);
# ({ role => 'tool', tool_call_id => 'call_1',
#    content => '# Project', is_error => False },)
```

Arguments may be a hash or the JSON string most APIs actually send; both are accepted, as is the empty string models send for a tool that takes none — that is a call with no arguments, not a broken one, and it runs. (A non-empty string that is not a JSON object is still an error result: the model asked for something the tool cannot be given.) Content blocks are flattened to the text a model reads, with binary payloads named rather than inlined — a base64 PNG in a transcript costs a fortune in tokens and tells the model nothing it can act on.

**`execute-tool-calls` never throws.** A malformed call, arguments that are not a JSON object, a tool the server does not have, a tool that reported `isError`, a timeout, an exhausted multi round-trip loop, a connection that has died — each becomes an entry with `is_error` set and the reason as its `content`. A model that can read what went wrong can try something else; an exception thrown into the middle of a tool round cannot be recovered from at all.

The calls also run **inside the method**, not when the caller first reads the answers: what comes back is a real `List`, so a batch that has returned is a batch that has already happened. Tools have side effects, and a lazily-reified batch would run them on whatever thread eventually looked at the result — or, for a run that was cancelled, never.

### The Registry

An agent with more than one tool source has two problems: two servers may both call their tool `search`, and the model must be told which one it is talking to. [MCP::Client::Registry](lib/MCP/Client/Registry.rakumod) gives every provider a prefix, rewrites the names it publishes to `{prefix}{sep}{name}`, and routes each call back to whichever provider owns the prefix it was made under.

`add` is duck-typed — a provider is anything with `tools-for-llm` and `execute-tool-calls`. That is satisfied by an `MCP::Client`, by an `MCP::Server` with no transport under it at all, by another registry (so registries nest), and by anything you write with those two methods. Since a registry satisfies the pair itself, it drops straight into a tool loop in place of a single client.

```raku
use MCP::Server;
use MCP::Server::Tool::FileSystem;
use MCP::Client;
use MCP::Client::Registry;

my $tools = MCP::Client::Registry.new;

$tools.add(MCP::Client.connect-stdio(command => 'mcp-server-git'), prefix => 'git');
$tools.add(MCP::Client.connect-http(url => 'https://tools.example.com/mcp'), prefix => 'corp');

my $local = MCP::Server.new(:name<local>, :version<1.0.0>);
$local.plug(MCP::Server::Tool::FileSystem.new(root => '/srv/docs'));
$tools.add($local, prefix => 'fs');

say $tools.tools-for-llm.map({ $_<function><name> });
# (git_log git_diff ... corp_search ... fs_read fs_write ...)

$tools.remove('corp');           # returns the provider, or Nil
say $tools.providers.map({ $_<prefix> });   # (git fs)
```

Routing is by longest matching prefix, so prefixes may be extensions of each other (`fs` and `fs_ext`) and tool names may contain the separator. Calls are batched per provider and threaded back into the order the model asked for them, so a model that interleaves calls to three servers still gets one result per call, in its own order. A provider that throws fails only its own calls.

### Permissions: the Policy

An agent that can write files is an agent that can write the wrong file. [MCP::Client::Policy](lib/MCP/Client/Policy.rakumod) is the Claude Code-shaped answer to that, client-side: reads go through, anything that changes the world stops at a prompt, and the human's answer can be remembered for the rest of the session.

It satisfies the same duck type the registry does, so it stacks anywhere a provider goes — over a client, over a registry, under a registry, or several deep with a different rule set at each layer:

```raku
use MCP::Client::Policy;

my $policy = MCP::Client::Policy.new(
    provider => $mcp,
    rules    => [
        |MCP::Client::Policy.default-rules,                        # reads, and asking
        { tool => 'fs_write',  decision => 'allow', under => 'scratch' },
        { tool => 'fs_delete', decision => 'deny' },
    ],
    roots  => { fs => '/srv' },      # tool-name prefix → the server's directory
    on-ask => &ask-the-user,
);

$policy.tools-for-llm;               # fs_delete is not on it
$policy.execute-tool-calls(@calls);  # allowed calls forwarded as one batch
```

A rule is `{ tool, decision, under? } `: an exact tool name or a trailing-`*` prefix glob, one of `allow`/`deny`/`ask`, and an optional directory the rule is about. Every matching rule is evaluated and the strongest decision wins — **deny > ask > allow**, so a serialized rule set can be merged and re-ordered without changing what it means — and **a call no rule matched is asked about**, never allowed.

Containment is **purely lexical**, segment by segment, and never touches the filesystem: the paths belong to the server's disk, and symlink truth is `MCP::Server::Tool::FileSystem`'s sandbox root to enforce, not this client's to second-guess. Segment-wise also means `/tmp/root2` is not inside `/tmp/root`, however much the strings agree.

The answer to "is it inside?" therefore has three values. `unknown` — a `..` segment, a null byte, a backslash, an absolute path with no root to measure it against, a missing or non-string argument, arguments that are not JSON — fails closed in both directions: an `allow` rule needs **every** location it was given to be `yes`, while a `deny` or `ask` rule fires on **any** `yes` or `unknown`.

`&on-ask` gets one seam and two kinds of question. A permission question carries the tool, the parsed arguments, a copy of the call, the rule that provoked it, the locations it names and a `suggestion` — the deepest directory containing everything the call touches — and is answered with `allow-once`, `deny-once`, `always-allow` or `always-deny`, the last two leaving a session grant behind. The other kind is the server's own elicitation, forwarded by `elicit-hook` and answered with a bare `ElicitResult`. Both go through one lock, because there is one human and they can answer one question at a time. That lock has no timeout — a human deliberating stalls every waiting batch, so a UI wanting a deadline imposes its own inside the callback — and it is non-reentrant: an `&on-ask` that dispatches another policy-mediated call from inside the prompt handler deadlocks on its own question. Treat the callback as a leaf.

```raku
my $policy;
my $mcp = MCP::Client.connect-stdio(
    command   => 'mcp-filesystem',
    args      => ['/srv'],
    on-elicit => -> %request { $policy.elicit-hook.(%request) },
);
$policy = MCP::Client::Policy.new(:provider($mcp), :&on-ask, roots => { fs => '/srv' });

$policy.grants;   # plain data: persist it, hand it back next session as `grants`
```

`&on-grant` is told when that list changes: it is handed the whole set (already copied) the moment an `always-` answer adds one, so a host does not have to poll `.grants` or infer it from an answer it watched go past. It fires while the call that provoked the grant is still being decided, which is what lets an engine mirror the grant into a session in time for the next call in the same batch — and, for the same reason, it is as much of a leaf as `&on-ask` is. A hook that throws is swallowed: the grant is already made, and a failed listener is no reason to refuse the call.

```raku
my $policy = MCP::Client::Policy.new(
    :$provider, :&on-ask,
    on-grant => -> @grants { spurt 'grants.json', to-json(@grants) },
);
```

Wire `on-elicit` **only** when there is somebody to ask — setting it is what declares the elicitation capability, and a server told it may ask will ask. `.interactive` is the guard. Headless, every `ask` outcome is an `is_error` result saying there was nobody to ask, which is a refusal the model can read rather than a hang.

Two things to know before wiring one up. Rules name tools **as this policy sees them**: a registry strips its prefix before passing a call on, so a policy under a registry sees `read` where a policy over it sees `fs_read`, and a rule at the wrong layer silently matches nothing (the symptom is everything asking). And grants are consulted **only** once the static rules have said `ask`, so an explicit `{ tool => '*', decision => 'ask' } ` rule means "keep asking" — which is why the default rules do not include one.

### A full tool loop

Everything above, wired to [LLM::Chat::ToolLoop](https://github.com/m-doughty/LLM_Chat). Note that `LLM::Chat` is **not** a dependency of this distribution — the bridge is a shape, not a coupling, and the same two methods drive any loop that speaks OpenAI-style function calling.

```raku
use MCP::Server;
use MCP::Server::Tool::FileSystem;
use MCP::Client;
use MCP::Client::Registry;
use LLM::Chat::ToolLoop;
use LLM::Chat::Conversation::Message;

# 1. A toolkit in this process. No transport, no serialisation, no subprocess.
my $local = MCP::Server.new(:name<local-tools>, :version<1.0.0>);
$local.plug(MCP::Server::Tool::FileSystem.new(root => '/srv/docs'));

# 2. A server on the other side of a pipe.
my $remote = MCP::Client.connect-stdio(
    command     => 'mcp-server-git',
    args        => ['--repository', '/srv/project'],
    client-name => 'my-agent',
    on-warn     => -> Str:D $m { note "mcp: $m" },
);
LEAVE $remote.close;

# 3. One namespace over both.
my $tools = MCP::Client::Registry.new;
$tools.add($local,  prefix => 'fs');
$tools.add($remote, prefix => 'git');

# 4. A model that cannot tell them apart.
my $loop = LLM::Chat::ToolLoop.new(
    :$backend,
    tools          => $tools.tools-for-llm,
    execute-tools  => -> @calls { $tools.execute-tool-calls(@calls) },
    on-tool-call   => -> %call   { note "→ {%call<function><name>}" },
    on-tool-result => -> %result { note "← {%result<content>}" },
);

my $answer = $loop.chat-completion-stream([
    LLM::Chat::Conversation::Message.new(
        role    => 'user',
        content => 'What changed in the docs since the last release?',
    ),
]);

react whenever $answer.supply -> $chunk { print $chunk }
```

`examples/toolloop.raku` is that program, runnable, with a scripted backend in place of a real model so it costs nothing and produces the same output every time.

Error handling
--------------

Everything this client raises on its own behalf is an `X::MCP::Client`, so one `CATCH` clause separates "the MCP conversation went wrong" from "the code around it went wrong". The subclasses carry the context you would otherwise have to scrape back out of a message string.

<table class="pod-table">
<thead><tr>
<th>Exception</th> <th>Raised when</th> <th>Carries</th>
</tr></thead>
<tbody>
<tr> <td>X::MCP::Client</td> <td>A misuse of this API: an unknown option, an invalid setting</td> <td>detail</td> </tr> <tr> <td>X::MCP::Client::Timeout</td> <td>A request outlived its budget. The connection survives it</td> <td>seconds, method, id</td> </tr> <tr> <td>X::MCP::Client::ServerGone</td> <td>The child process exited, or the connection died, with work outstanding</td> <td>exit-code, signal, command, stderr-tail</td> </tr> <tr> <td>X::MCP::Client::Protocol</td> <td>A JSON-RPC error, or a reply the protocol does not allow</td> <td>code, data</td> </tr> <tr> <td>X::MCP::Client::UnsupportedVersion</td> <td>No overlap between the versions we speak and the ones the server speaks</td> <td>requested, supported</td> </tr> <tr> <td>X::MCP::Client::Cancelled</td> <td>The caller kept the cancelled promise</td> <td>method, id</td> </tr> <tr> <td>X::MCP::Client::InputLoopExceeded</td> <td>A multi round-trip request kept asking past max-input-rounds</td> <td>rounds, method</td> </tr> <tr> <td>X::MCP::Client::TransportClosed</td> <td>close was called, or a failure took the connection with it</td> <td>detail</td> </tr> <tr> <td>X::MCP::Client::SpawnFailed</td> <td>The server command could not be started</td> <td>command, args</td> </tr>
</tbody>
</table>

A tool that fails is **not** on that list: `isError` is a result. Nor is a model-facing failure — `execute-tool-calls` converts every one of the above into an `is_error` entry rather than throwing.

```raku
use MCP::Client;
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
        when X::MCP::Client::Protocol {
            note "server refused: {.message} (code {.code // 'none'})";
            note "  it offers: " ~ (.data<supported> // []).join(', ')
                if .code.defined && .code == -32022;
        }
        when X::MCP::Client {
            note "MCP failure: {.^name}: {.message}";
        }
    }
    $mcp.call-tool('flaky', {});
}
```

`.stderr-tail` is the one worth wiring into any operator-facing log. A misconfigured stdio server — a missing API key, a bad path, a node version it cannot run under — writes the entire diagnosis to stderr and then exits, and that tail is the only place it survives.

Limitations
-----------

Each of these is a decision, and each has a reason. None of them is a bug report.

  * **No legacy Streamable HTTP.** The HTTP transport is 2026-07-28 only: no `Mcp-Session-Id`, no `GET` stream, no `Last-Event-ID` resumability, no HTTP+SSE. Legacy servers in the wild are overwhelmingly stdio, and stdio is dual-era here, so a legacy server is not locked out of the client — only out of this transport.

  * **No `subscriptions/listen`.** A subscription's only job is pushing cache invalidation, and `ttlMs` expiry is spec-compliant without it. The cost is staleness bounded by the TTL the server itself chose, and `:refresh` is always available.

  * **No tasks extension.** `io.modelcontextprotocol/tasks` — long-running work polled through a task id — is not implemented. A long tool call is a long request here, bounded by its timeout.

  * **No OAuth.** There is no authorization-server flow, no token refresh, no dynamic client registration. Static credentials go in `connect-http`'s `%headers`; anything richer belongs in front of the endpoint.

  * **`ping` is legacy-only.** 2026-07-28 removed the utility, so against a modern server it reports `False` ("the server does not implement it") rather than liveness. Liveness in the modern era belongs to the transport.

  * **Elicitation is declared form-mode only** unless `%.client-capabilities` says otherwise, because URL-mode elicitation asks the client to open a browser.

Testing
-------

```shell
prove6 -I. t                                   # against installed dependencies, as CI does
prove6 -Ilib -It/lib -I../MCP-Server/lib t/    # against a sibling MCP-Server checkout
```

Sixteen files, from the protocol units up: a scripted transport double for the era machine and the round-trip loop, an in-process transport that puts the client in front of a live `MCP::Server` with no wire between them, a real child process for the stdio transport (including one that kills itself mid-request), and a live HTTP server on a random port.

Four of them are cross-checks rather than unit tests. `t/13` is a golden-parity test: the same toolkit behind a local `MCP::Server` and behind an `MCP::Client` must produce identical bridge output, which is what makes "interchangeable" a claim rather than a hope. `t/14` puts a policy over that same live server, including a real elicitation answered through `elicit-hook`, and re-runs `t/13`'s argument shapes through an allow-everything policy to pin the two argument parsers together. `t/15` runs the multi round-trip loop against an `MCP::Server` that really does elicit — the client half of the contract, checked against the server half rather than against a script. `t/16` does the same for progress, against a server whose tools really do report it, and pins the other half of "when does a tool call happen": that a batch has finished running by the time `execute-tool-calls` returns.

The fixtures under `t/lib` are reusable, and are meant to be: `t/lib` on the include path gives you `MCP::Client::Test::FakeTransport` (scripted answers, and notifications you can push at a client whenever you like), `MCP::Client::Test::InProcessTransport` (a live `MCP::Server`, no wire), `MCP::Client::Test::TestKit` (one tool of every shape) and `MCP::Client::Test::ProgressKit` (tools that report progress, for testing anything built on the `on-progress` hook).

The example is runnable too, and needs no network and no API key:

```shell
raku -Ilib -It/lib -I../MCP-Server/lib -I../LLM-Chat/lib -I../Template-Jinja2/lib \
     examples/toolloop.raku
```

Author
------

Matt Doughty

License
-------

Artistic-2.0

