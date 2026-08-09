=begin pod

=head1 NAME

MCP::Client::Registry - one tool namespace over many MCP providers

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client;
use MCP::Client::Registry;

my $tools = MCP::Client::Registry.new;

# A remote server, spawned as a child process...
$tools.add(
	MCP::Client.connect-stdio(command => 'mcp-filesystem', args => ['/srv']),
	prefix => 'fs',
);

# ...and a toolkit running in this very process. Both look the same from here.
my $local = MCP::Server.new(:name<local>, :version<1.0.0>);
$local.plug(MCP::Server::Tool::Shell.new);
$tools.add($local, prefix => 'sh');

say $tools.tools-for-llm.map({ $_<function><name> });
# (fs_read_file fs_write_file ... sh_run ...)

$tools.execute-tool-calls([
	{ id => 'call_1', function => { name => 'fs_read_file', arguments => '{"path":"/srv/x"}' } },
]);
=end code

=head1 DESCRIPTION

An agent with more than one tool source has two problems: two servers may both
call their tool C<search>, and the model must be told which one it is talking
to. A registry solves both by giving every provider a prefix, rewriting the
names it publishes to C<{prefix}{sep}{name}>, and routing a call back to
whichever provider owns the prefix it was made under.

The prefix convention is C<MCP::Server>'s own — C<$server.plug($kit,
:prefix<x>)> namespaces a toolkit exactly this way — so a tool called
C<fs_read_file> means the same thing whether C<fs> was applied when the toolkit
was plugged into a server or when the server was added to a registry.

=head2 Anything that speaks the bridge

C<add> is duck-typed: a provider is anything with a C<tools-for-llm> method and
an C<execute-tool-calls> method. That is deliberately the smallest possible
contract, and it is satisfied by:

=item an C<MCP::Client> — a remote server over stdio or HTTP;
=item an C<MCP::Server> — a toolkit running in this process, with no transport
      anywhere;
=item another C<MCP::Client::Registry>, because a registry satisfies the pair
      too, so registries nest;
=item anything you write that implements the two methods.

Since the registry is itself a provider, it drops straight into
C<LLM::Chat::ToolLoop> in place of a single client:

=begin code :lang<raku>
use LLM::Chat::ToolLoop;

my $loop = LLM::Chat::ToolLoop.new(
	backend       => $backend,
	tools         => $tools.tools-for-llm,
	execute-tools => -> @calls { $tools.execute-tool-calls(@calls) },
	on-tool-call  => -> %call { note "→ %call<function><name>" },
);

my $stream = $loop.chat-completion-stream(@messages);
react whenever $stream.supply -> $chunk { print $chunk }
=end code

=head2 Routing

A call is routed by the longest registered prefix that its function name starts
with, so prefixes may be extensions of each other and names may contain the
separator without ambiguity. With C<fs> and C<fs_ext> both registered under the
default C<_> separator:

=begin code :lang<raku>
$tools.add($basic,    prefix => 'fs');       # tag "fs_"
$tools.add($extended, prefix => 'fs_ext');   # tag "fs_ext_"

# fs_read_file  → $basic, called as "read_file"
# fs_ext_read   → $extended, called as "read"     (the longer tag wins)
=end code

The prefix is stripped before the call is handed on, so a provider never sees a
name it did not publish, and never has to know it is inside a registry.

Calls are batched: every call for one provider is passed to it in a single
C<execute-tool-calls>, in the order the model asked for them, and the results
are threaded back into the original positions. A model that interleaves calls to
three servers still gets one result per call, in its own order.

=head2 Failure

Nothing a provider does makes C<execute-tool-calls> throw:

=item a call naming a prefix nobody registered comes back as an C<is_error>
      result;
=item a malformed call — not an object, or with no C<function> — comes back as
      an C<is_error> result;
=item a provider that throws (a dead connection, a bug) fails B<only its own
      calls>: every other provider's results are unaffected;
=item a provider that returns fewer results than it was given calls has the
      gaps filled with C<is_error> results, so the caller always gets exactly
      one result per call.

C<tools-for-llm> is the exception, and on purpose: a provider that cannot list
its tools throws, because silently publishing a shorter tool list would leave a
model wondering why a capability it was told about yesterday has vanished. Wrap
the call if you would rather degrade than fail.

=head1 EXAMPLES

Take a provider away again — an MCP server that has gone down, a toolkit
switched off by configuration — and the tool list shrinks accordingly:

=begin code :lang<raku>
my $gone = $tools.remove('fs');    # the provider, or Nil if there was none
$gone.close if $gone ~~ MCP::Client;

say $tools.providers.map({ $_<prefix> });    # (sh)
=end code

Group several servers under one prefix by nesting:

=begin code :lang<raku>
my $vendor = MCP::Client::Registry.new;
$vendor.add($jira, prefix => 'jira');
$vendor.add($slack, prefix => 'slack');

$tools.add($vendor, prefix => 'corp');
# corp_jira_search, corp_slack_post, ...
=end code

=end pod

use MCP::Client::Exceptions;

unit class MCP::Client::Registry;

# What a prefix and a separator may be made of. The same alphabet MCP::Server
# enforces on a tool name (and the one the OpenAI-compatible function-calling
# APIs accept), checked here rather than at dispatch time: a prefix that cannot
# appear in a legal tool name would publish a whole provider under names the
# model can never call back.
my $PREFIX-ALPHABET = rx/^ <[A..Za..z0..9_-]>+ $/;

has Lock $!lock .= new;
has      @!entries;

#| Register a provider under a prefix. Everything it publishes is renamed
#| C<{prefix}{sep}{name}>, and every call made under that prefix is routed back
#| to it with the prefix stripped.
#|
#| The provider is duck-typed: anything with C<tools-for-llm> and
#| C<execute-tool-calls> qualifies, which an C<MCP::Client>, an C<MCP::Server>
#| and another C<MCP::Client::Registry> all do.
#|
#| Dies if the provider does not implement the pair, if the prefix is already
#| taken, or if another provider already occupies the same C<{prefix}{sep}>
#| namespace (C<fs> + C<_x> and C<fs_> + C<x> both publish C<fs_x...>, and
#| there would be no way to route between them).
#|
#| Returns the registry, so C<add> chains.
method add($provider, Str:D :$prefix!, Str:D :$sep = '_' --> MCP::Client::Registry:D) {
	die X::MCP::Client.new(
		detail => 'a registry prefix cannot be empty',
	) unless $prefix.chars;

	die X::MCP::Client.new(
		detail => "invalid registry prefix '$prefix': prefixes must be made of "
			~ 'letters, digits, underscores and hyphens',
	) unless $prefix ~~ $PREFIX-ALPHABET;

	die X::MCP::Client.new(
		detail => "invalid registry separator '$sep': separators must be empty or made of "
			~ 'letters, digits, underscores and hyphens',
	) unless $sep eq '' || $sep ~~ $PREFIX-ALPHABET;

	# .can rather than .^can: both answer for a normal class, and .can is what
	# a provider built out of a role, a mixin or a delegating handles-trait
	# answers correctly.
	die X::MCP::Client.new(
		detail => "cannot register {$provider.defined ?? 'a ' ~ $provider.^name !! 'the ' ~ $provider.^name ~ ' type object'} "
			~ "under the prefix '$prefix': a tool provider must be a defined object with "
			~ 'both a tools-for-llm and an execute-tool-calls method',
	) unless $provider.defined && provider-shaped($provider);

	my $tag = $prefix ~ $sep;

	$!lock.protect: {
		die X::MCP::Client.new(
			detail => "a provider is already registered under the prefix '$prefix'",
		) if @!entries.first({ $_<prefix> eq $prefix }).defined;

		die X::MCP::Client.new(
			detail => "the prefix '$prefix' with separator '$sep' publishes tools as '$tag*', "
				~ 'which another registered provider already does',
		) if @!entries.first({ $_<tag> eq $tag }).defined;

		@!entries.push: %( :$provider, :$prefix, :$sep, :$tag );
	}

	self;
}

#| Unregister the provider held under a prefix and return it, or C<Nil> if that
#| prefix was never registered. The provider is not closed or shut down — it is
#| the caller's, and it may well be registered somewhere else too.
method remove(Str:D $prefix) {
	$!lock.protect: {
		my $at = @!entries.first({ $_<prefix> eq $prefix }, :k);
		# Branches rather than a variable: assigning Nil to a scalar stores the
		# scalar's default (Any) instead, and "there was no such prefix" is
		# worth saying in the type.
		if $at.defined {
			my $provider = @!entries[$at]<provider>;
			@!entries.splice($at, 1);
			$provider;
		}
		else {
			Nil;
		}
	}
}

#| Every registered provider in registration order, each as
#| C<{ prefix, sep, provider }>.
method providers(--> List:D) {
	$!lock.protect: {
		@!entries.map({ %( prefix => $_<prefix>, sep => $_<sep>, provider => $_<provider> ) }).List;
	}
}

#| How many providers are registered.
method elems(--> Int:D) {
	$!lock.protect: { @!entries.elems }
}

#| True when a prefix is taken.
method has-prefix(Str:D $prefix --> Bool:D) {
	$!lock.protect: { @!entries.first({ $_<prefix> eq $prefix }).defined }
}

# === The bridge ===

#| Every provider's tool declarations, concatenated in registration order, with
#| each C<function.name> rewritten to C<{prefix}{sep}{name}>.
#|
#| Throws whatever a provider throws while listing: see the note on failure in
#| the description.
method tools-for-llm(--> List) {
	my @out;

	for self!snapshot -> %entry {
		for %entry<provider>.tools-for-llm.list -> $tool {
			@out.push: prefixed-tool($tool, %entry<tag>);
		}
	}

	@out.List;
}

#| Route each call to the provider that owns its prefix, run it there, and
#| return the results in the order the calls came in — one result per call,
#| whatever happened.
#|
#| Never throws. A call for an unregistered prefix, a malformed call, and every
#| call in the batch of a provider that threw all come back as C<is_error>
#| results.
method execute-tool-calls(@tool-calls --> List) {
	my @entries = self!snapshot;
	my @results;
	my %batches;

	for @tool-calls.kv -> $index, $call {
		my $function = $call ~~ Associative ?? $call<function> !! Any;
		my $id = $call ~~ Associative ?? ($call<id> // '') !! '';

		unless $function ~~ Associative && $function<name> ~~ Str:D {
			@results[$index] = error-result(
				$id,
				'Malformed tool call: expected an object with a function name',
			);
			next;
		}

		my $name = $function<name>;
		my %entry = longest-match(@entries, $name);

		unless %entry {
			@results[$index] = error-result(
				$id,
				"Unknown tool: '$name' (no registered provider owns that prefix)",
			);
			next;
		}

		# The provider is handed a call it could have received directly: same
		# id, same arguments, and the name it published under. Copied rather
		# than edited in place -- the call belongs to the caller, and the model
		# transcript it came from still refers to the prefixed name.
		my %function = $function.Hash;
		%function<name> = $name.substr(%entry<tag>.chars);
		my %inner = $call.Hash;
		%inner<function> = %function;

		%batches{%entry<prefix>} //= [];
		%batches{%entry<prefix>}.push: %( :$index, :$id, call => %inner );
	}

	# Dispatched in registration order rather than in %batches order, so a batch
	# that has side effects has them in an order that does not depend on hash
	# iteration.
	for @entries -> %entry {
		my $batch = %batches{%entry<prefix>};
		next without $batch;

		my @calls = $batch.map({ $_<call> }).List;
		my @answers;
		my $failure;
		{
			CATCH { default { $failure = $_ } }
			@answers = %entry<provider>.execute-tool-calls(@calls).list;
		}

		for $batch.kv -> $at, %item {
			@results[%item<index>] = $failure.defined
				?? error-result(
					%item<id>,
					"The '{%entry<prefix>}' tool provider failed: {$failure.message}",
				)
				!! normalized-result(@answers[$at], %item<id>);
		}
	}

	@results.List;
}

# A copy of the entry table taken under the lock, so a dispatch already under
# way cannot be disturbed by an add or a remove on another thread -- the same
# discipline the store uses for walks: mutate the table, never the walk.
method !snapshot(--> List:D) {
	$!lock.protect: { @!entries.map(*.Hash).List };
}

# Whether an object implements the bridge pair. The whole of the provider
# contract, and deliberately structural: MCP::Client, MCP::Server and
# MCP::Client::Registry share no ancestor and should not have to.
my sub provider-shaped($provider --> Bool:D) {
	so $provider.can('tools-for-llm') && $provider.can('execute-tool-calls');
}

# The entry whose tag the name starts with, longest first. Longest wins because
# a shorter registered prefix may be a prefix of a longer one ("fs" and
# "fs_ext"), and because a tool name may itself contain the separator.
my sub longest-match(@entries, Str:D $name --> Hash:D) {
	my %best;
	for @entries -> %entry {
		next unless $name.starts-with(%entry<tag>);
		%best = %entry if !%best || %entry<tag>.chars > %best<tag>.chars;
	}
	%best;
}

# One tool declaration, republished under a tag. A declaration that does not
# carry a function name is passed through untouched: there is nothing to
# prefix, and dropping a provider's entry would hide the fact that it published
# something odd.
my sub prefixed-tool($tool, Str:D $tag) {
	return $tool unless $tool ~~ Associative;

	my %tool = $tool.Hash;
	return %tool unless %tool<function> ~~ Associative;

	my %function = %tool<function>.Hash;
	return %tool unless %function<name> ~~ Str:D;

	%function<name> = $tag ~ %function<name>;
	%tool<function> = %function;
	%tool;
}

my sub error-result($id, Str:D $content --> Hash:D) {
	{
		role => 'tool',
		tool_call_id => $id,
		content => $content,
		is_error => True,
	};
}

# A provider's answer, made safe to hand on. Providers that honour the bridge
# contract pass through untouched; the rest are patched up rather than trusted,
# because the caller is owed one well-formed result per call.
my sub normalized-result($answer, $id --> Hash:D) {
	return {
		role => 'tool',
		tool_call_id => $id,
		content => 'The tool provider returned no result for this call',
		is_error => True,
	} without $answer;

	unless $answer ~~ Associative {
		return {
			role => 'tool',
			tool_call_id => $id,
			content => ~$answer,
			is_error => False,
		};
	}

	my %result = $answer.Hash;
	%result<role> = 'tool' unless %result<role>:exists;
	%result<tool_call_id> = $id unless %result<tool_call_id>:exists;
	%result;
}
