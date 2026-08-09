#!/usr/bin/env raku

=begin pod

=head1 NAME

toolloop.raku - one tool namespace over a local toolkit and a remote MCP server

=head1 SYNOPSIS

=begin code :lang<shell>
raku -Ilib -It/lib -I../MCP-Server/lib -I../LLM-Chat/lib -I../Template-Jinja2/lib \
     examples/toolloop.raku
=end code

=head1 DESCRIPTION

An end-to-end run of the thing this distribution exists for: a model asks for
tools, some of them run in this process and some of them run inside a server
that is a separate operating-system process, and neither the model nor the
loop driving it can tell which is which.

Three parts:

=item B<A local toolkit> — an ordinary C<MCP::Server> with two tools and no
      transport at all. It never serialises anything; the registry calls its
      bridge methods directly.
=item B<A remote server> — C<t/lib/fixture-server.raku>, spawned as a child
      process and spoken to over stdio by an C<MCP::Client>. Its tools come
      from C<MCP::Client::Test::TestKit>.
=item B<A scripted model> — a C<LLM::Chat::Backend> that emits a fixed
      sequence of tool calls instead of talking to an API, so the run is
      deterministic and costs nothing.

C<MCP::Client::Registry> puts the first two behind one prefixed namespace and
hands the pair of bridge methods to C<LLM::Chat::ToolLoop>.

C<LLM::Chat> is deliberately not a dependency of this distribution — the bridge
is a shape (C<tools-for-llm> / C<execute-tool-calls>), not a coupling. That is
why this example is run with an explicit C<-I../LLM-Chat/lib> rather than
against an installed C<MCP::Client>.

=head2 Why a scripted backend

C<LLM::Chat::Backend::Mock> replays canned B<text>: its C<@.responses> are
C<Str>, and nothing in it sets C<tool_calls> or a C<tool_calls> finish reason,
so it can never drive a tool round. C<ScriptedBackend> below is the smallest
backend that can — one step per backend call, each step either a list of tool
calls or the final text — and is adapted from the one in C<LLM-Chat>'s own
C<t/17-tool-loop.rakutest>.

=end pod

use MCP::Server;

use MCP::Client;
use MCP::Client::Registry;
use MCP::Client::Transport::Stdio;

use LLM::Chat::Backend;
use LLM::Chat::Backend::Response;
use LLM::Chat::Backend::Response::Stream;
use LLM::Chat::Backend::Settings;
use LLM::Chat::Conversation::Message;
use LLM::Chat::ToolLoop;

# Everything printed by this example goes through here. The tool hooks fire on
# the tool loop's thread while the main thread waits, and two threads writing to
# $*OUT with no lock between them is how output arrives interleaved mid-line.
my $out-lock = Lock.new;
sub put-line(Str:D $line --> Nil) {
	$out-lock.protect: { say $line };
}

# === The local half: a toolkit with no transport under it ====================

sub local-server(--> MCP::Server:D) {
	my $server = MCP::Server.new(name => 'local-tools', version => '1.0.0');

	$server.tool: 'add',
		description => 'Add two integers',
		params => {
			a => { type => 'integer', description => 'First addend', required => True },
			b => { type => 'integer', description => 'Second addend', required => True },
		},
		handler => -> :%args { ((%args<a> // 0) + (%args<b> // 0)).Str };

	$server.tool: 'upcase',
		description => 'Upper-case a string',
		params => {
			text => { type => 'string', description => 'Text to shout', required => True },
		},
		handler => -> :%args { (%args<text> // '').Str.uc };

	$server;
}

# === The remote half: a real server in a real child process ==================

# The fixture is found relative to this file, so the example runs from anywhere.
constant FIXTURE = $?FILE.IO.parent.parent.add('t/lib/fixture-server.raku').absolute;

# The child needs the same -I paths this process was started with: it loads
# MCP::Server and MCP::Client::Test::TestKit, which from a checkout are sibling
# directories rather than installed distributions.
sub include-args(--> List) {
	$*REPO.repo-chain
		.grep(* ~~ CompUnit::Repository::FileSystem)
		.map({ '-I' ~ .prefix.absolute })
		.List;
}

sub remote-client(--> MCP::Client:D) {
	MCP::Client.connect-stdio(
		# $*EXECUTABLE, not 'raku': the child must be the same rakudo running
		# this script, whether or not one is on PATH.
		command     => $*EXECUTABLE.absolute,
		args        => [|include-args(), FIXTURE, '--era=both'],
		client-name => 'toolloop-example',
		on-stderr   => -> Str:D $line { note "[fixture stderr] $line" },
		on-warn     => -> Str:D $message { note "[mcp] $message" },
	);
}

# === The model =============================================================

#| A backend that replays a script instead of calling an API. Each step is
#| either C<< { tool-calls => [...] } >> — a round in which the model asks for
#| tools — or C<< { content => '...' } >>, the answer it settles on.
class ScriptedBackend is LLM::Chat::Backend {
	has @.steps is rw;
	has Int $!next-id = 0;

	method chat-completion(
		@messages where all(@messages) ~~ LLM::Chat::Conversation::Message,
		:@tools,
		--> LLM::Chat::Backend::Response
	) {
		die 'ScriptedBackend only implements streaming';
	}

	method chat-completion-stream(
		@messages where all(@messages) ~~ LLM::Chat::Conversation::Message,
		:@tools,
		--> LLM::Chat::Backend::Response::Stream
	) {
		my $id = 'scripted-' ~ ++$!next-id;
		my $response = LLM::Chat::Backend::Response::Stream.new(:$id);
		my %step = @!steps.elems ?? @!steps.shift !! %(content => '');

		start {
			with %step<content> -> $content {
				$response.emit($content) if $content.chars;
			}

			if %step<tool-calls>:exists {
				$response._set-tool-calls(%step<tool-calls>.list);
				$response._set-finish-reason('tool_calls');
			}
			else {
				$response._set-finish-reason('stop');
			}

			$response.done;
		}

		$response;
	}
}

# A tool call in the shape every OpenAI-compatible API sends one: arguments are
# a JSON *string*, not an object. The bridge accepts both.
sub call(Str:D $id, Str:D $name, %arguments --> Hash:D) {
	use JSON::Fast;
	{
		id => $id,
		type => 'function',
		function => { name => $name, arguments => to-json(%arguments, :!pretty, :sorted-keys) },
	};
}

# === The run ================================================================

sub MAIN() {
	my $remote = remote-client();

	# The client is closed however this exits -- a normal return, an exception,
	# or a control exception -- because the child process is ours to reap.
	LEAVE $remote.close;

	my $tools = MCP::Client::Registry.new;
	$tools.add(local-server(), prefix => 'local');
	$tools.add($remote, prefix => 'remote');

	put-line "Remote server: {$remote.server-info<name>} {$remote.server-info<version>}"
		~ " (protocol era: {$remote.era})";
	put-line '';

	# Sorted for display only. A remote catalogue arrives in a deterministic
	# order (MCP::Server sorts tools/list by name), but a local server's
	# tools-for-llm walks its own hash, so the two halves of this namespace do
	# not agree on what "unordered" looks like. Nothing depends on the order --
	# a model reads names, not positions -- but an example whose output changes
	# between runs is a bad example.
	put-line 'Tools offered to the model:';
	for $tools.tools-for-llm.sort({ .<function><name> }) -> %tool {
		put-line sprintf('  %-18s %s', %tool<function><name>,
			%tool<function><description> // '');
	}
	put-line '';

	my $backend = ScriptedBackend.new(
		settings => LLM::Chat::Backend::Settings.new,
		steps => [
			# One round, two calls, two different providers. The registry
			# batches them per provider and threads the results back into the
			# order the model asked for them.
			{
				tool-calls => [
					call('call_1', 'local_add', { a => 2, b => 3 }),
					call('call_2', 'remote_echo', { text => 'hello from the loop' }),
				],
			},
			# A tool that fails is a result, not an exception: the loop carries
			# on and the model gets to read what went wrong.
			{
				tool-calls => [
					call('call_3', 'remote_dying', { reason => 'nothing works' }),
					call('call_4', 'remote_absent', { }),
				],
			},
			{ content => '2 + 3 = 5, the remote server echoed the text back, ' ~
				'and the two failing calls reported why.' },
		],
	);

	my $loop = LLM::Chat::ToolLoop.new(
		:$backend,
		tools => $tools.tools-for-llm,
		execute-tools => -> @calls { $tools.execute-tool-calls(@calls) },
		on-tool-call => -> %tool-call {
			put-line "  → {%tool-call<function><name>} {%tool-call<function><arguments>}";
		},
		on-tool-result => -> %result {
			put-line "  ← {%result<is_error> ?? 'ERROR: ' !! ''}{%result<content>}";
		},
	);

	put-line 'Tool loop:';
	my $answer = $loop.chat-completion-stream([
		LLM::Chat::Conversation::Message.new(
			role => 'user',
			content => 'Add 2 and 3, echo something remotely, then try the broken tools.',
		),
	]);

	# Bounded: an example that hangs forever tells nobody anything.
	my $deadline = now + 60;
	sleep 0.01 until $answer.is-done || now > $deadline;

	put-line '';
	put-line $answer.is-done
		?? "Final answer: {$answer.msg}"
		!! 'Final answer: (the loop did not finish within 60 seconds)';
}

# Expected output. The loop announces every call in a round before it executes
# any of them, so the arrows come in pairs of calls followed by pairs of
# results rather than strictly alternating:
#
# Remote server: fixture-server 0.1.0 (protocol era: modern)
#
# Tools offered to the model:
#   local_add          Add two integers
#   local_upcase       Upper-case a string
#   remote_banner      Print a line of non-JSON to stdout, then answer normally
#   remote_crash       Write to stderr and exit the process mid-request
#   remote_dying       Throw, so the isError path can be tested
#   remote_echo        Return the text it was given
#   remote_gate_open   Release whoever is waiting on the gate
#   remote_gate_wait   Block until gate_open is called
#   remote_noisy       Emit a log notification, then answer
#   remote_slow        Answer after a delay
#
# Tool loop:
#   → local_add {"a":2,"b":3}
#   → remote_echo {"text":"hello from the loop"}
#   ← 5
#   ← hello from the loop
#   → remote_dying {"reason":"nothing works"}
#   → remote_absent {}
#   ← ERROR: nothing works
#   ← ERROR: Unknown tool: 'absent'
#
# Final answer: 2 + 3 = 5, the remote server echoed the text back, and the two
# failing calls reported why.
