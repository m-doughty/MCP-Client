=begin pod

=head1 NAME

MCP::Client::Reasons - every tool call carries why, for the human watching

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Reasons;
use MCP::Client::Policy;

my $policy = MCP::Client::Policy.new(
	provider => MCP::Client::Reasons.new(provider => $registry),
	rules    => MCP::Client::Policy.default-rules,
	:&on-ask,
);

# The model now writes:
#   fs_write { "path": "src/app.raku", "content": "...",
#              "reason": "Add the missing guard clause you asked for" }
#
# The permission prompt sees the reason (it is in the call's arguments), the
# tool card renders it, and the server is handed the call without it.
=end code

=head1 DESCRIPTION

A tool call tells you what an agent is about to do. It does not tell you why,
and "why" is most of what a human needs in order to answer a permission prompt
in less than a minute — C<fs_write> to C<config/app.yml> is either the change
that was asked for or the beginning of a bad afternoon, and the arguments look
the same either way.

C<MCP::Client::Reasons> is the smallest thing that gets the why: it adds one
optional C<reason> parameter to every tool declaration on the way out, and
deletes it from every call on the way in. The model fills it in because it is
declared where the model is looking; the UI reads it off the call it is about
to render; the server never learns the parameter exists.

It is a provider composer, satisfying the same duck type
C<MCP::Client::Registry> and C<MCP::Client::Policy> do — C<tools-for-llm> plus
C<execute-tool-calls> — so it stacks in wherever a provider goes.

=head2 What it does to the catalogue

Each declaration it can read gains one property:

=begin code :lang<raku>
reason => {
	type        => 'string',
	description => 'One short sentence: why this call. Shown to the human ' ~
	               'reviewing the session.',
}
=end code

It is B<never> added to C<required>. A model that omits it makes a call that is
still valid, and a turn is never spent on a schema error over a field that
exists for a human's benefit. The declaration is copied rather than edited, so
the provider's own catalogue objects are not mutated under it.

A declaration this layer cannot read is passed through B<exactly> as it came
and is not tracked: no C<function>, no string C<name>, no C<parameters> object,
or a C<properties> that is not an object. There is no schema there to extend
without inventing one, and inventing one is how a layer meant to be invisible
starts breaking servers.

=head2 The collision rule

A tool that already declares its own C<reason> parameter is left B<completely
alone> — not augmented, and, more importantly, not stripped. Its C<reason> is a
real argument that its server expects to receive, and a layer that deleted it
on the way past would corrupt every call to it in a way nobody would think to
look for.

That is the general rule this layer is built on: B<when in doubt, do not
strip>. A parameter removed from a call that needed it is a silent
misbehaviour; a parameter left on a call that did not expect it is the server's
own validation problem, reported to the model as an ordinary tool error.

The same reasoning applies to a tool that lists C<reason> in C<required>
without declaring it — an odd schema, but one whose author plainly means
something by the name, so it is left alone too.

=head2 Which calls get stripped

The ones whose tool name was augmented by the B<most recent> C<tools-for-llm>.
That set is instance state, replaced wholesale under a lock each time the
catalogue is listed, so a refresh that adds or removes a tool downstream is
reflected in what gets stripped from the next batch.

Everything else forwards with its arguments untouched, and untouched means the
very object the caller passed: a call to a tool this layer has never seen
listed, a call to a collision tool, a call whose arguments are not a JSON
object, a call with no C<reason> in them. Only a call that actually carries a
C<reason> for an augmented tool is rebuilt, and then only far enough to drop
that one key.

Arguments arrive in the two shapes the bridges accept — an object, or the JSON
string a model's function call actually travels as (with the empty string
meaning "no arguments", exactly as C<MCP::Client> and C<MCP::Server> read it).
A string is re-serialised compactly after the key is dropped, so a stripped
call is preserved by B<value>, not byte for byte; every other call is passed on
byte for byte because it is passed on unchanged.

=head2 The reason is a claim, not evidence

It is written by the model, about the model's own intentions, in the same
sampling step as the arguments. It is not a signature, an audit record or a
justification anybody checked. Two consequences, both deliberate:

=item B<A UI must keep the arguments primary.> Render the reason as
      supporting text next to the command, the path and the diff — never
      instead of them, and never in a way that lets a human approve a call
      having read only the reason. A model that is wrong about what it is doing
      writes a sincere reason for the wrong call, and a model that has been
      talked into something by a poisoned document writes a persuasive one.

=item B<Machine policy must never consume it.> The rule engine, the danger
      floor and the auto-mode classifier all decide on the tool name, the
      arguments and the paths — never on this field. A permission layer that
      read the reason would be a permission layer the model could talk its way
      through by writing nicer sentences, which is precisely the property the
      static rules exist to not have.

=head2 Where in the stack

Directly B<under> the policy and B<over> everything else:

=begin code :lang<raku>
Policy( Reasons( Subagents( Escalation( Leases( Registry ) ) ) ) )
=end code

Under the policy, because the policy's C<&on-ask> request carries a copy of the
call, and the call still has the C<reason> in its arguments at that point —
which is the entire reason this layer exists. Put it B<over> the policy and the
prompt shows the human a call with no reason in it, having stripped the field
before the question was asked.

Under, though, not necessarily B<directly> under: a non-mutating layer such as
L<MCP::Client::UnknownKeys|lib/MCP/Client/UnknownKeys.rakumod> may sit between
the two, because a layer that rewrites neither the declarations on the way out
nor the arguments on the way down leaves the reason exactly where C<&on-ask>
finds it.

Over everything else, because everything else is a provider whose tools should
be augmented too. Over the subagent composer, and the C<task> tool gains a
C<reason> like any other — delegating is one of the calls a human most wants
the why of. Over the lease layer, the escalation layer and the registry, so no
layer that inspects arguments (locating paths, matching commands) ever sees a
parameter that is not the server's.

Because the strip happens at forward time and nowhere else, the reason stays in
the assistant message the model produced: the recorded C<tool_calls> keep it,
so a session transcript, a replay and a resumed run all still have it with no
schema change anywhere. Read it back with the parameter name this module
publishes as C<MCP::Client::Reasons::REASON-PARAM>.

=head2 Never throws

C<execute-tool-calls> keeps the provider contract exactly: an inner provider
that died becomes one C<is_error> result per call, in the caller's own order,
and results that came back are passed through as they came. C<tools-for-llm>
keeps the deliberate asymmetry: an inner provider that cannot list its tools
throws, because publishing a silently shorter catalogue leaves a model
wondering where a capability went.

=head1 EXAMPLES

The whole of the wiring, in a stack that also delegates and locks:

=begin code :lang<raku>
my $reasons = MCP::Client::Reasons.new(
	provider => MCP::Client::Leases.new(inner => $registry, :$table, :$agent-id),
);

my $policy = MCP::Client::Policy.new(
	provider => $reasons,
	rules    => @preset-rules,
	on-ask   => -> %request {
		# %request<arguments><reason> is the model's sentence, when it wrote one.
		$ui.ask(%request);
	},
);
=end code

A UI reading the reason off a call it is rendering — from the recorded
C<tool_calls>, which is where it still is:

=begin code :lang<raku>
use MCP::Client::Reasons;
use JSON::Fast;

sub reason-of($call) {
	my $raw = $call<function><arguments>;
	my %args = $raw ~~ Associative ?? $raw.Hash !! (try from-json($raw)) // {};
	%args{MCP::Client::Reasons::REASON-PARAM} // '';
}
=end code

Which tools are being augmented right now — the set the last catalogue listing
left behind, useful in a test and in a "why is this not being stripped?"
diagnosis:

=begin code :lang<raku>
$reasons.tools-for-llm;
say $reasons.augmented-tools;    # (fs_read fs_write ... task)
=end code

=head1 SEE ALSO

L<MCP::Client::Policy|lib/MCP/Client/Policy.rakumod> — the permission layer
this one stacks under, and the C<&on-ask> request whose C<arguments> carry the
reason to the human.

L<MCP::Client::Leases|lib/MCP/Client/Leases.rakumod> — another composer in the
same stack, sitting below this one.

=end pod

use JSON::Fast;

use MCP::Client::Exceptions;

unit class MCP::Client::Reasons;

#| The parameter this layer adds and strips. Published so a UI reading the
#| reason back out of a recorded tool call names the same key this layer does.
our constant REASON-PARAM = 'reason';

# Written for the model, and every word of it is load-bearing: "one short
# sentence" keeps it from turning into a paragraph that costs tokens on every
# call, and naming the human tells the model who the audience is -- which is
# what stops it explaining the JSON back to itself.
my constant REASON-DESCRIPTION =
	'One short sentence: why this call. Shown to the human reviewing the session.';

# Everything .new accepts. Named rather than inferred so that a typo --
# `providers` for `provider` -- is an error at construction instead of a layer
# that quietly augments nothing.
my constant OPTIONS = <provider>.Set;

has $.provider is required;

has Lock $!lock .= new;

# The tool names augmented by the most recent tools-for-llm, and therefore the
# names a `reason` is stripped from. Replaced wholesale under the lock rather
# than edited, so a batch deciding concurrently with a refresh sees one listing
# or the other, never half of each.
has %!augmented;

submethod TWEAK(:$provider, *%unknown) {
	my @unknown = %unknown.keys.grep({ !OPTIONS{$_} }).sort;
	die X::MCP::Client.new(
		detail => "unknown option(s) for a reason layer: '{@unknown.join(q{', '})}'; a reason "
			~ 'layer is made of ' ~ OPTIONS.keys.sort.join(', '),
	) if @unknown;

	# .can rather than .^can, and structural rather than nominal: the same
	# contract MCP::Client::Policy and MCP::Client::Registry check, for the same
	# reason -- a client, a server, a registry and a policy share no ancestor.
	die X::MCP::Client.new(
		detail => 'cannot build a reason layer over '
			~ ($!provider.defined ?? 'a ' ~ $!provider.^name !! 'the ' ~ $!provider.^name ~ ' type object')
			~ ': a tool provider must be a defined object with both a tools-for-llm and an '
			~ 'execute-tool-calls method',
	) unless $!provider.defined && provider-shaped($!provider);
}

#| The tool names the last C<tools-for-llm> augmented, sorted — the exact set a
#| C<reason> is stripped from on the way down. Empty until the catalogue has
#| been listed at least once.
method augmented-tools(--> List:D) {
	$!lock.protect: { %!augmented.keys.sort.List };
}

# === The bridge ===

#|( The inner provider's declarations, each with an optional C<reason> string
    parameter added to C<parameters.properties> — never to C<required>.

    A declaration that already has a C<reason> parameter (or names one in
    C<required>) is passed through untouched and is B<not> tracked, so its
    own C<reason> is never stripped from a call on the way back down. So is
    one this layer cannot read: no function, no string name, no
    C<parameters> object, or a C<properties> that is not an object.

    The set of names augmented here replaces the previous one, so a refresh
    that adds or drops a downstream tool is reflected in what the next
    batch is stripped of.

    Throws whatever the inner provider throws while listing. )
method tools-for-llm(--> List) {
	my @published = $!provider.tools-for-llm.list;

	my %augmented;
	my @out;

	for @published -> $tool {
		my $name = augmentable-name($tool);

		unless $name.defined {
			@out.push: $tool;
			next;
		}

		%augmented{$name} = True;
		@out.push: with-reason($tool);
	}

	$!lock.protect: { %!augmented = %augmented };

	@out.List;
}

#|( Every call, forwarded as one batch with the model's C<reason> removed from
    the ones this layer added it to — and one result per call, in the
    caller's order, as the inner provider gave them.

    A call whose tool was not augmented is forwarded as the very object the
    caller passed. So is one that carries no C<reason>, and one whose
    arguments are not a JSON object: this layer rebuilds a call only when it
    has a key to drop from it.

    B<Never throws.> An inner provider that died comes back as one
    C<is_error> result per call. )
method execute-tool-calls(@tool-calls --> List) {
	# Nothing asked for is nothing to forward: an empty batch is not handed on,
	# so a provider that logs or wakes something up on each batch is not woken
	# by a layer that had no work of its own.
	return ().List unless @tool-calls;

	# Snapshot once, so a catalogue refresh landing mid-batch cannot strip half
	# the calls in it and leave the rest.
	my %augmented = $!lock.protect: { %!augmented.Hash };

	my @forward = @tool-calls.map({ stripped($_, %augmented) }).List;

	my @answers;
	my $failure;
	{
		CATCH { default { $failure = $_ } }
		# `.eager`, and it is not decoration: a provider that hands back a lazy
		# list has not done the work yet, and reifying it below -- outside this
		# CATCH -- would turn a provider that throws into an exception this
		# method promises never to raise.
		@answers = $!provider.execute-tool-calls(@forward).list.eager;
	}

	my @results;
	for @tool-calls.kv -> $index, $call {
		my $id = $call ~~ Associative ?? ($call<id> // '') !! '';

		if $failure.defined {
			@results[$index] = error-result(
				$id,
				'The tool provider failed: ' ~ ($failure.message.lines.head // $failure.^name),
			);
			next;
		}

		# Passed through as it came: this layer adds no shape of its own,
		# because the layer above (a policy, a registry) already normalises and
		# a second opinion would only differ. The exception is a missing answer
		# -- one result per call is the contract, and a provider that came up
		# short must not leave a hole in the caller's list.
		my $answer = @answers[$index];
		@results[$index] = $answer.defined
			?? $answer
			!! error-result($id, 'The tool provider returned no result for this call');
	}

	@results.List;
}

# === Declarations ===

# The tool name of a declaration this layer may augment, or an undefined Str
# for one it must leave alone -- unreadable, or already carrying a `reason` of
# its own. Both answers mean "not tracked", which is what keeps the strip and
# the augmentation exactly in step.
my sub augmentable-name($tool --> Str) {
	return Str unless $tool ~~ Associative;

	my $function = $tool<function>;
	return Str unless $function ~~ Associative && $function.defined;
	return Str unless $function<name> ~~ Str:D;

	my $parameters = $function<parameters>;
	return Str unless $parameters ~~ Associative && $parameters.defined;

	my $properties = $parameters<properties>;
	# Absent is fine -- a tool that takes no arguments is still a tool a human
	# wants the why of -- but present-and-not-an-object is a schema this layer
	# cannot reason about.
	return Str if $properties.defined && !($properties ~~ Associative);
	return Str if $properties.defined && ($properties{REASON-PARAM}:exists);

	# `required` naming a parameter the schema does not declare is an odd
	# schema, but its author plainly means something by the name. Left alone in
	# both directions rather than argued with.
	my $required = $parameters<required>;
	return Str if $required ~~ Positional && $required.list.first(* eqv REASON-PARAM).defined;

	$function<name>;
}

# One declaration, with the reason parameter added. Copied down the path it
# touches -- tool, function, parameters, properties -- and shared everywhere
# else: the provider's catalogue objects are the provider's, and a layer that
# edited them in place would leave the reason behind in a catalogue somebody
# else is about to publish unaugmented.
my sub with-reason($tool --> Hash:D) {
	my %tool = $tool.Hash;
	my %function = %tool<function>.Hash;
	my %parameters = %function<parameters>.Hash;

	my %properties = %parameters<properties> ~~ Associative && %parameters<properties>.defined
		?? %parameters<properties>.Hash
		!! %();
	%properties{REASON-PARAM} = %(
		type        => 'string',
		description => REASON-DESCRIPTION,
	);

	%parameters<properties> = %properties;
	# A schema with properties and no type is legal-ish and common enough from
	# hand-written declarations; naming the type it must have costs nothing and
	# saves a strict validator from refusing the catalogue.
	%parameters<type> = 'object' unless %parameters<type> ~~ Str:D;

	# `required` is deliberately untouched. An optional field is one a model can
	# forget without spending a turn on a schema error, and this one is for a
	# human's benefit rather than the tool's.
	%function<parameters> = %parameters;
	%tool<function> = %function;
	%tool;
}

# === Stripping ===

# One call on its way down, with the reason removed if this layer put the
# parameter there and the model filled it in. Every other call comes back as
# the very object it went in as.
my sub stripped($call, %augmented) {
	return $call unless $call ~~ Associative;

	my $function = $call<function>;
	return $call unless $function ~~ Associative;

	my $name = $function<name>;
	return $call unless $name ~~ Str:D && %augmented{$name};

	my $raw = $function<arguments>;

	# Already an object: the shape a caller that parsed the model's JSON itself
	# hands on, and the one the in-process bridges use.
	if $raw ~~ Associative {
		return $call unless $raw{REASON-PARAM}:exists;

		my %arguments = $raw.Hash;
		%arguments{REASON-PARAM}:delete;
		return rebuilt($call, $function, %arguments);
	}

	# Undefined, or the empty string models send for a tool that takes no
	# arguments: nothing to strip, and nothing to normalise either -- turning
	# '' into '{}' here would change what the bridge below sees for every
	# call, not just the ones this layer is about.
	return $call without $raw;
	return $call if $raw.Str.trim eq '';

	my $parsed;
	{
		CATCH { default { $parsed = Nil } }
		$parsed = from-json($raw.Str);
	}

	# Arguments that will not parse, or that are not an object, are the inner
	# provider's problem to report -- and are certainly not something to guess
	# a reason out of.
	return $call unless $parsed ~~ Associative;
	return $call unless $parsed{REASON-PARAM}:exists;

	my %arguments = $parsed.Hash;
	%arguments{REASON-PARAM}:delete;

	# Re-serialised compactly and with sorted keys: a stripped call is preserved
	# by value rather than byte for byte (JSON object key order carries no
	# meaning), and determinism beats echoing whatever whitespace the model
	# happened to emit.
	rebuilt($call, $function, to-json(%arguments, :!pretty, :sorted-keys), :as-json);
}

# A copy of a call with new arguments in it, edited no deeper than it has to be.
my sub rebuilt($call, $function, $arguments, Bool :$as-json --> Hash:D) {
	my %function = $function.Hash;
	%function<arguments> = $as-json ?? $arguments !! $arguments.Hash;

	my %call = $call.Hash;
	%call<function> = %function;
	%call;
}

# === Helpers ===

# Whether an object implements the bridge pair: the whole of the provider
# contract, and the same test MCP::Client::Policy makes.
my sub provider-shaped($provider --> Bool:D) {
	so $provider.can('tools-for-llm') && $provider.can('execute-tool-calls');
}

my sub error-result($id, Str:D $content --> Hash:D) {
	%(
		role => 'tool',
		tool_call_id => $id,
		content => $content,
		is_error => True,
	);
}
