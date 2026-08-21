=begin pod

=head1 NAME

MCP::Client::UnknownKeys - surface arguments a tool never declared, without
touching the call

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Policy;
use MCP::Client::Reasons;
use MCP::Client::UnknownKeys;

my $policy = MCP::Client::Policy.new(
	provider => MCP::Client::UnknownKeys.new(
		provider => MCP::Client::Reasons.new(provider => $registry),
		on-warn  => -> %warning {
			$log.warning(
				"{%warning<tool>} was called with undeclared argument(s): "
					~ %warning<unknown-keys>.join(', ')
			);
		},
	),
	rules => MCP::Client::Policy.default-rules,
	:&on-ask,
);

# A provider that mangled a call into
#   task { "prompt": "Investigate the", "nvestigate": "…", "the rest": "…" }
# still runs exactly as it would have without this layer -- and says so once.
=end code

=head1 DESCRIPTION

A model's tool call arrives as a JSON object, and nothing in the loop between
the sampler and the server has to agree about what is in it. A truncated
generation that a constrained decoder closed into I<valid> JSON, a provider
that re-serialised the arguments through a lossy intermediate shape, a model
that invented a plausible-sounding parameter: all three produce a call whose
keys are not the keys the tool declared, and all three used to arrive at a
server that quietly ignored the extras and did four fifths of the job.

C<MCP::Client::UnknownKeys> is the smallest thing that makes that visible. It
compares each call's argument keys against the properties the tool's own
declaration published, and when a call carries a key the tool never declared it
calls C<&on-warn> once. Then it forwards the call — B<the same object, with the
same arguments> — to the provider beneath it, and returns that provider's
results exactly as they came.

It is a provider composer, satisfying the same duck type
C<MCP::Client::Registry> and C<MCP::Client::Policy> do — C<tools-for-llm> plus
C<execute-tool-calls> — so it stacks in wherever a provider goes.

=head2 It is a smoke alarm, not a valve

Nothing this layer notices changes what happens. It does not reject the call,
does not strip the key, does not rewrite the arguments, does not add a result,
does not delay the batch, and does not turn an unknown key into an error a
model has to interpret. A tool that ignores an extra argument goes on ignoring
it; a tool that refuses one goes on refusing it, in its own words.

That is a deliberate division of labour rather than timidity. Rejection is
right where the cost of acting on a mangled call is unbounded and the argument
list is known exactly — spawning a subagent on a truncated brief, say, which is
why the delegation tool validates strictly on its own account. For the rest of
a toolkit, a client-side refusal would be a second opinion about somebody
else's schema: MCP servers are free to accept arguments they do not advertise,
declarations arrive from servers this client did not write, and a layer that
refused a call the server would have honoured breaks working setups to prevent
a hypothetical one. So: warn, forward, and let the log say whether stricter
handling is ever warranted.

=head2 What it audits, and what it says nothing about

A call is audited only when B<all> of these hold, and skipped silently
otherwise:

=item Its tool appeared in the most recent C<tools-for-llm> pass-through. A
      tool this layer has never seen listed has no declaration to check
      against, so it is never audited — including every call made before the
      catalogue was listed for the first time.
=item That declaration carried a C<parameters.properties> object with at least
      one property in it. A tool with no declared properties is either
      argument-free or schema-free; in both cases every key is equally
      undeclared, and warning about all of them would be noise standing in for
      an answer.
=item Its arguments read as a JSON object — either an object already, or the
      JSON string a model's function call actually travels as. Arguments that
      will not parse, that parse to something other than an object, that are
      the empty string a model sends for an argument-free call, or that are
      absent altogether, are B<not> this layer's to complain about: they are
      the provider's to report, in the vocabulary the provider already has.

C<reason> is always tolerated, declared or not. It is the parameter
L<MCP::Client::Reasons|lib/MCP/Client/Reasons.rakumod> adds to declarations on
the way out and removes from calls on the way down, so a stack with reasons
switched on legitimately produces calls carrying a key no server ever declared.
The name is a literal here rather than an import, so this layer works in a
stack that has no reason layer in it at all — the two are independent.

=head2 Where in the stack

Between the policy and the reason layer:

=begin code :lang<raku>
Policy( UnknownKeys( Reasons( ...( Registry ) ) ) )
=end code

Both neighbours are load-bearing, because this layer compares two things that
are rewritten at different heights.

B<Under the policy>, so the arguments it reads are the model's own. The policy
is the last layer that sees a call before anything narrows it, and it is also
what the human answers a prompt about; auditing beneath it means the keys
compared are the keys the model actually emitted.

B<Over the reason layer>, so the declarations it caches are the ones the model
was shown. The reason layer adds C<reason> to every declaration it can read on
the way out and strips it from every call on the way down. Sitting over it, the
C<tools-for-llm> that fills this layer's cache sees the B<augmented> schemas, so
a C<reason> in a call matches a declared property and nothing is reported;
sitting under it, the calls would already have been stripped and the cache
would carry an undeclared C<reason>. Either seat is safe — the literal
tolerance covers both, and this layer is correct with reasons on or off — but
this one is the seat where neither half of the comparison has been rewritten
behind its back.

It cannot usefully sit lower. The registry has no declaration cache to share
and never sees the tools a composer above it publishes on its own account
(a delegation tool, a lease tool), so a layer seated there would audit part of
the catalogue and be blind to the rest. Above the policy it would see calls the
policy is about to refuse and, worse, would sit over the layer whose grants and
preset rules name tools by the very names it is trying to check.

=head2 The warning

C<&on-warn> is handed one hash and its answer is ignored:

=begin table
Key             | What it is
================|=====================================================
tool            | The tool name, as the catalogue published it
unknown-keys    | The undeclared keys B<being reported now>, sorted
declared-keys   | Every property the declaration published, sorted
id              | The call's C<id>, or the empty string when it has none
=end table

It defaults to a one-line C<note>, which is the right default for a script and
the wrong one for a host: a host with a log, an event stream or a session
record should pass its own and put the warning where a human will find it
later.

The callback is B<shielded>. One that throws is swallowed, because a broken bit
of host bookkeeping must never change what a tool call does — which is the
whole promise this layer is built on.

=head2 Said once

Each C<(tool, unknown key)> pair is reported B<once per instance>, and an
instance is a session's stack. A model that has decided C<fs_read> takes a
C<recursive> flag will decide it again on every call, and a warning per call
would bury the first one. A B<new> key on the same tool is a new fact and is
reported; so is the same key on a different tool.

C<unknown-keys> therefore carries the keys being reported for the first time,
not every undeclared key on the call — the ones already said are not repeated
in a warning about something else.

The seen-set is never cleared, not even by a catalogue refresh. A refresh can
only stop a key being unknown (by declaring it), and a key that has stopped
being unknown does not need announcing again.

=head2 Never throws, never blocks

C<execute-tool-calls> is transparent in both directions. Every call is
forwarded, in the caller's order, as the very object the caller passed, and
whatever the inner provider returns is returned unchanged — including an empty
batch, which is passed on rather than short-circuited, so a provider that logs
or wakes something on each batch behaves exactly as it would with this layer
absent. An inner provider that throws throws through: this layer adds no error
shape of its own, because the layer above it already has one and a second
opinion would only differ from it.

The audit itself cannot fail the call. It holds a lock only long enough to
claim a warning as said, never while calling C<&on-warn> and never across the
forward, and any exception raised while reading a call's own arguments is
swallowed — an unreadable call is one this layer has nothing to say about, not
one it gets to break.

C<tools-for-llm> keeps the deliberate asymmetry the other composers keep: an
inner provider that cannot list its tools throws, because publishing a silently
shorter catalogue leaves a model wondering where a capability went. The
declaration cache is replaced only when a listing succeeded.

=head1 EXAMPLES

The incident this layer exists for, in miniature — a provider that closed a
truncated generation into valid JSON, so the loop's own length gate never
fired:

=begin code :lang<raku>
my @warnings;
my $audited = MCP::Client::UnknownKeys.new(
	provider => $registry,
	on-warn  => -> %warning { @warnings.push: %warning },
);

$audited.tools-for-llm;   # fills the cache; fs_read declares path, offset

$audited.execute-tool-calls([
	%(
		id => 'call_1',
		function => %(
			name => 'fs_read',
			arguments => '{"path":"src/app.raku","ffset":12,"the rest":"…"}',
		),
	),
]);

# The read still happened, at the path the model asked for.
say @warnings[0]<unknown-keys>;    # (ffset the rest)
say @warnings[0]<declared-keys>;   # (offset path)
=end code

Wiring it to a host's own log, which is what a host should do — a one-line
C<note> is a script's default, not a session's record:

=begin code :lang<raku>
my $audited = MCP::Client::UnknownKeys.new(
	provider => $inner,
	on-warn  => -> %warning {
		$session.log(
			level   => 'warning',
			message => "{%warning<tool>} ({%warning<id>}) carried undeclared "
				~ "argument(s) {%warning<unknown-keys>.join(', ')}; it declares "
				~ %warning<declared-keys>.join(', '),
		);
	},
);
=end code

Which tools are being audited right now — the set the last catalogue listing
left behind, useful in a test and in a "why did this not warn?" diagnosis:

=begin code :lang<raku>
$audited.tools-for-llm;
say $audited.audited-tools;   # (fs_read fs_write task)
=end code

=head1 SEE ALSO

L<MCP::Client::Policy|lib/MCP/Client/Policy.rakumod> — the permission layer
this one stacks under.

L<MCP::Client::Reasons|lib/MCP/Client/Reasons.rakumod> — the layer directly
beneath, whose C<reason> parameter this one tolerates by name.

=end pod

use JSON::Fast;

use MCP::Client::Exceptions;

unit class MCP::Client::UnknownKeys;

# The parameter MCP::Client::Reasons adds to every declaration on the way out
# and strips from every call on the way down -- published there as
# MCP::Client::Reasons::REASON-PARAM, and repeated here as a literal rather
# than imported so this layer works in a stack with no reason layer in it. The
# two are pinned together by a test.
my constant REASON-PARAM = 'reason';

# Everything .new accepts. Named rather than inferred so that a typo --
# `on-warning` for `on-warn` -- is an error at construction instead of a layer
# that audits everything and tells nobody.
my constant OPTIONS = <provider on-warn>.Set;

# The %!said key of one (tool, key) pair. NUL because it cannot occur in either
# half: a JSON string may contain any character, so a separator that a tool
# name or a property key could contain would let two different pairs share an
# entry and silence a warning that was never said.
my constant SAID-SEPARATOR = "\0";

has $.provider is required;

#|( Called once per (tool, undeclared key), with one hash: C<tool>,
    C<unknown-keys>, C<declared-keys>, C<id>. Its answer is ignored.

    Defaults to a one-line C<note>, which is a script's default rather than a
    host's: anything with a log or an event stream should pass its own.

    B<Shielded>: a callback that throws is swallowed, because a broken bit of
    host bookkeeping must not change what a tool call does. )
has &.on-warn = -> %warning {
	note 'mcp: ' ~ %warning<tool> ~ ' was called with undeclared argument(s) '
		~ %warning<unknown-keys>.join(', ') ~ '; it declares '
		~ (%warning<declared-keys>.elems ?? %warning<declared-keys>.join(', ') !! 'none');
};

has Lock $!lock .= new;

# Tool name -> the Set of property keys its declaration published, from the
# most recent tools-for-llm. Replaced wholesale under the lock rather than
# edited, so a batch auditing concurrently with a refresh compares against one
# listing or the other, never half of each.
has %!properties;

# The (tool, key) pairs already reported, so a model with a habit reports it
# once. Never cleared: a refresh can only stop a key being unknown.
has %!said;

submethod TWEAK(:$provider, :&on-warn, *%unknown) {
	my @unknown = %unknown.keys.grep({ !OPTIONS{$_} }).sort;
	die X::MCP::Client.new(
		detail => "unknown option(s) for an unknown-key layer: '{@unknown.join(q{', '})}'; an "
			~ 'unknown-key layer is made of ' ~ OPTIONS.keys.sort.join(', '),
	) if @unknown;

	# .can rather than .^can, and structural rather than nominal: the same
	# contract MCP::Client::Policy and MCP::Client::Registry check, for the same
	# reason -- a client, a server, a registry and a policy share no ancestor.
	die X::MCP::Client.new(
		detail => 'cannot build an unknown-key layer over '
			~ ($!provider.defined ?? 'a ' ~ $!provider.^name !! 'the ' ~ $!provider.^name ~ ' type object')
			~ ': a tool provider must be a defined object with both a tools-for-llm and an '
			~ 'execute-tool-calls method',
	) unless $!provider.defined && provider-shaped($!provider);

	# Checked here rather than discovered at call time, because a callback that
	# cannot be called is swallowed by the shield: a wrong-shaped on-warn would
	# otherwise be a layer that silently never warns, which is indistinguishable
	# from a stack that has nothing to warn about.
	die X::MCP::Client.new(
		detail => 'the on-warn of an unknown-key layer must accept one argument -- the warning '
			~ 'hash -- and this one takes ' ~ &!on-warn.arity ~ ' to ' ~ &!on-warn.count,
	) unless &!on-warn.arity <= 1 <= &!on-warn.count;
}

#| The tool names the last C<tools-for-llm> cached a declaration for, sorted —
#| the exact set of tools whose calls are audited. Empty until the catalogue
#| has been listed at least once, which is why nothing is audited before then.
method audited-tools(--> List:D) {
	$!lock.protect: { %!properties.keys.sort.List };
}

# === The bridge ===

#|( The inner provider's declarations, B<unmodified> — the same objects, in the
    same order, in a list of this layer's own.

    Every readable declaration's C<parameters.properties> keys are cached as
    the argument names that tool declares. One without an Associative
    C<properties> is passed on like any other and simply not cached, so its
    calls are never audited.

    The cache replaces the previous one, so a refresh that adds a property, a
    tool, or drops either is reflected in what the next batch is audited
    against.

    Throws whatever the inner provider throws while listing, and leaves the
    previous cache in place when it does. )
method tools-for-llm(--> List) {
	my @published = $!provider.tools-for-llm.list;

	my %properties;
	for @published -> $tool {
		my ($name, $declared) = declared-properties($tool);
		next without $name;

		%properties{$name} = $declared;
	}

	$!lock.protect: { %!properties = %properties };

	@published.List;
}

#|( Every call, forwarded to the inner provider exactly as it came — the same
    objects, in the same order — with the inner provider's results returned
    exactly as they came.

    On the way past, a call whose tool has a cached declaration and whose
    arguments read as a JSON object is compared against that declaration, and
    C<&on-warn> is called once per (tool, undeclared key). C<reason> is always
    tolerated.

    B<Nothing about the audit reaches the call.> It cannot refuse one, rewrite
    one, delay one or fail one; an inner provider that throws throws through
    this layer unchanged. )
method execute-tool-calls(@tool-calls) {
	self!audit(@tool-calls);

	$!provider.execute-tool-calls(@tool-calls);
}

# === The audit ===

# Everything this layer does on its own account, and none of it may reach the
# call. The whole body is shielded: reading a call's arguments means indexing
# objects a caller built, and one that throws on being read is one this layer
# has nothing to say about -- not one it gets to break.
method !audit(@tool-calls --> Nil) {
	CATCH { default { } }

	return unless @tool-calls;

	# Snapshot once, outside the lock: a listing landing mid-batch cannot audit
	# half the calls against one catalogue and half against the next, and the
	# JSON parsing below never happens while anything else is waiting.
	my %declared = $!lock.protect: { %!properties.Hash };
	return unless %declared;

	my @warnings;

	for @tool-calls -> $call {
		# Shielded per call as well as per batch: reading one call a caller built
		# out of something exotic must not silence the warnings the rest of the
		# batch had. The loop carries on at the next call.
		CATCH { default { } }

		my $name = tool-name($call);
		next without $name;

		my $properties = %declared{$name};
		# Not listed, or listed with no declared properties at all: in the first
		# case there is nothing to compare against, and in the second everything
		# would be undeclared, which is noise standing in for an answer.
		next without $properties;
		next unless $properties.elems;

		my @keys = argument-keys($call);
		next unless @keys;

		my @unknown = @keys.grep({ $_ ne REASON-PARAM && !$properties{$_} }).sort;
		next unless @unknown;

		# The claim and the warning are separated deliberately: the lock is held
		# for a hash lookup and never while a host's callback runs.
		my @fresh = $!lock.protect: {
			my @new = @unknown.grep({ !%!said{said-key($name, $_)} }).List;
			%!said{said-key($name, $_)} = True for @new;
			@new;
		};
		next unless @fresh;

		@warnings.push: %(
			tool            => $name,
			'unknown-keys'  => @fresh.List,
			'declared-keys' => $properties.keys.sort.List,
			id              => id-of($call),
		);
	}

	warn-about($_, &!on-warn) for @warnings;

	Nil;
}

# === Declarations ===

# A declaration's tool name and the Set of property keys it publishes, or an
# undefined name for one this layer cannot read: no function, no string name,
# no parameters object, or a properties that is not an object. A tool with no
# properties key at all is cached as the empty set -- it is a tool this layer
# saw, and the empty set is exactly what an argument-free tool declares.
my sub declared-properties($tool) {
	return (Str, Nil) unless $tool ~~ Associative;

	my $function = $tool<function>;
	return (Str, Nil) unless $function ~~ Associative && $function.defined;
	return (Str, Nil) unless $function<name> ~~ Str:D;

	my $parameters = $function<parameters>;
	return (Str, Nil) unless $parameters ~~ Associative && $parameters.defined;

	my $properties = $parameters<properties>;
	return ($function<name>, set()) without $properties;
	# Present and not an object is a schema this layer cannot reason about, and
	# guessing at one is how a layer meant to be invisible starts inventing
	# warnings nobody can act on.
	return (Str, Nil) unless $properties ~~ Associative;

	($function<name>, $properties.keys.Set);
}

# === Calls ===

# The tool name of a call, or an undefined Str for one there is no name to
# audit under.
my sub tool-name($call --> Str) {
	return Str unless $call ~~ Associative;

	my $function = $call<function>;
	return Str unless $function ~~ Associative && $function.defined;

	$function<name> ~~ Str:D ?? $function<name> !! Str;
}

# The argument keys of a call, in the two shapes the bridges accept: an object,
# or the JSON string a model's function call actually travels as. Anything else
# -- absent, the empty string a model sends for an argument-free call, a string
# that will not parse, a parse that is not an object -- is no keys, because it
# is the provider's to report rather than this layer's to guess at.
my sub argument-keys($call --> List:D) {
	my $function = $call<function>;
	my $raw = $function<arguments>;

	return $raw.keys.List if $raw ~~ Associative;
	return ().List without $raw;
	return ().List if $raw.Str.trim eq '';

	my $parsed;
	{
		CATCH { default { $parsed = Nil } }
		$parsed = from-json($raw.Str);
	}

	$parsed ~~ Associative ?? $parsed.keys.List !! ().List;
}

my sub id-of($call --> Str:D) {
	my $id = $call ~~ Associative ?? $call<id> !! Str;
	$id.defined ?? $id.Str !! '';
}

# === Helpers ===

my sub said-key(Str:D $tool, Str:D $key --> Str:D) {
	$tool ~ SAID-SEPARATOR ~ $key;
}

# One host callback, called for effect and never for an answer. Shielded here
# rather than at the call site because there is exactly one contract to keep
# and it is absolute: nothing a host's logging does may change a tool call.
my sub warn-about(%warning, &on-warn --> Nil) {
	CATCH { default { } }
	&on-warn(%warning);
	Nil;
}

# Whether an object implements the bridge pair: the whole of the provider
# contract, and the same test MCP::Client::Policy makes.
my sub provider-shaped($provider --> Bool:D) {
	so $provider.can('tools-for-llm') && $provider.can('execute-tool-calls');
}
