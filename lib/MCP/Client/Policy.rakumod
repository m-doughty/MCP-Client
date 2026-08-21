=begin pod

=head1 NAME

MCP::Client::Policy - per-directory permissions in front of any tool provider

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client;
use MCP::Client::Policy;

my $mcp = MCP::Client.connect-stdio(command => 'mcp-filesystem', args => ['/srv']);

my $policy = MCP::Client::Policy.new(
	provider => $mcp,
	rules    => [
		|MCP::Client::Policy.default-rules,                             # reads, and asking
		{ tool => 'fs_write',  decision => 'allow', under => 'scratch' },
		{ tool => 'fs_delete', decision => 'deny' },
	],
	roots   => { fs => '/srv' },
	on-ask  => &ask-the-user,
);

# A provider itself: it goes wherever the client or the registry went.
$policy.tools-for-llm;
$policy.execute-tool-calls([
	{ id => 'call_1', function => { name => 'fs_write',
	                                arguments => '{"path":"scratch/notes.md"}' } },
]);
=end code

=head1 DESCRIPTION

An agent that can write files is an agent that can write the wrong file. The
usual answer — the one Claude Code made familiar — is to ask: reads go through,
anything that changes the world stops at a prompt, and the human's answer can
be remembered for the rest of the session. This is that, as a provider you wrap
around another provider.

C<MCP::Client::Policy> satisfies the same duck type C<MCP::Client::Registry>
does — C<tools-for-llm> plus C<execute-tool-calls> — so it stacks anywhere a
provider goes: over a single client, over a registry, under a registry, or
several deep, with a different rule set at each layer.

The B<hard> boundary stays where it belongs: on the server, in
C<MCP::Server::Tool::FileSystem>'s sandbox root, which no client-side rule can
widen. This is the second, softer question — not "could this call escape?" but
"did the human agree to this one?" — and it is asked here because the server
cannot ask it. A server has nobody to ask.

=head2 The three answers

Every call is evaluated against the rules by
L<MCP::Client::Policy::Rules|lib/MCP/Client/Policy/Rules.rakumod>, which
answers C<allow>, C<deny> or C<ask> — see that module for the rule schema, the
lexical containment test and its tri-state, and the fail-closed semantics.
What this class adds is everything stateful:

=item B<allow> — the call is forwarded, untouched, in the same batch as every
      other allowed call in the round;
=item B<deny> — the call comes back as an C<is_error> result saying who refused
      it and why. The provider never sees it;
=item B<ask> — the session grants are consulted, and if they have nothing to
      say the C<&on-ask> callback is. Its answer decides the call, and may
      leave a grant behind for the rest of the session.

Grants are consulted B<only when the static rules said C<ask>>. That is what
makes an explicit C<< { tool => '*', decision => 'ask' } >> rule mean "ask me
every time" rather than "ask me until I say always" — but it also means such a
rule quietly defeats the remembering, which is why it is not the default (the
engine already asks about anything no rule matched).

=head2 One seam, two kinds of question

C<&on-ask> is called with a hash whose C<kind> says what is being asked. A
permission question:

=begin code :lang<raku>
{
	kind       => 'permission',
	tool       => 'fs_write',
	arguments  => { path => 'scratch/notes.md' },     # the parsed copy
	call       => { id => 'call_1', function => {...} },  # a copy of the original
	rule       => { tool => 'fs_*', decision => 'ask' },  # or an undefined Hash
	reason     => 'rule',            # or 'no-match' or 'unevaluable-path'
	paths      => ('/srv/scratch/notes.md',),
	suggestion => { tool => 'fs_write', under => '/srv/scratch' },
}
=end code

answered with one of:

=begin code :lang<raku>
{ action => 'allow-once' }
{ action => 'deny-once' }
{ action => 'always-allow' }                          # remembers the suggestion
{ action => 'always-deny', rule => { tool => 'fs_*', under => '/srv/live' } }
{ action => 'always-allow', rules => [                # several, in one answer
	{ tool => 'fs_write', under => '/srv' },
	{ tool => 'fs_edit',  under => '/srv' },
] }
=end code

C<rule> defaults to C<suggestion>, and the C<decision> of a remembered rule is
taken from the action rather than from the rule, so a UI need only say what the
human clicked. Anything else — an unknown action, a rule that will not
validate, a callback that throws, no callback at all — is a refusal of B<this
call only>, phrased in a way the model can read and act on.

C<rules> is the plural of C<rule>, for the coarse offers a UI makes when the
suggestion is too fine-grained to be useful — "allow edits and new directories
anywhere under the workspace" is four rules and one click. Every rule in it is
validated exactly as a single one is, and the answer is B<all or nothing>: one
unusable rule refuses this call and remembers none of them, because half a
grant is not what the human agreed to. An empty C<rules>, or an answer carrying
both C<rule> and C<rules>, is the same kind of refusal. C<&.on-grant> fires once
per answer however many rules it carried.

The other kind is a server's own elicitation, forwarded from
C<MCP::Client>'s C<on-elicit> hook by C<elicit-hook>:

=begin code :lang<raku>
{ kind => 'server-elicit', request => { method => 'elicitation/create', params => {...} } }
=end code

answered with a bare C<ElicitResult> — C<< { action => 'accept', content =>
{...} } >>, C<< { action => 'decline' } >> or C<< { action => 'cancel' } >>.
Both kinds go through the same lock, because there is one human and they can
only answer one question at a time.

Two consequences of that lock are worth designing around. First, an ask has
B<no timeout>: C<MCP::Client>'s per-call timeout budget stops at the wire and
does not cover a human deliberating, so a batch (and any concurrent batch, and
any server elicitation) waits as long as the question stays open — a UI that
wants a deadline must impose its own inside C<&on-ask>. Second, the lock is a
plain non-reentrant C<Lock>: an C<&on-ask> callback that re-enters the same
policy — dispatching a policy-mediated tool call from inside the prompt
handler, say — deadlocks on its own question, with no diagnostic. Treat the
callback as a leaf: collect the answer, return, and only then let the
application do more work.

What the queue does B<not> do is put the same question twice. The effective
grants are read again the moment the lock is acquired, so the calls that were
waiting behind an C<always-allow> or C<always-deny> answer are decided by the
grant it left rather than re-asked: C<&on-ask> is not called again, C<&on-grant>
does not fire again, and nothing further is remembered — deciding by a grant
never was an event. Ask six agents about the same directory at once and the
human answers once. A host that asks the human B<itself>, in its own bracket of
locks rather than through C<&on-ask>, wants the same check by hand before it
opens a dialog: that is C<grant-decision>.

A C<suggestion> is the deepest directory that really contains every path in
the call, so it can be as wide as C<'/'> when nothing narrower is true (an
absolute path with no configured root, for instance). A UI should render the
suggested directory rather than assume it is narrow.

A call that named no directory but B<did> name a website — a C<web_fetch> and
its C<url> — is suggested by C<host> instead: C<< { tool => 'web_fetch', host
=> 'docs.raku.org' } >>, so that "always allow" means this site and not the
web. Never both, and neither when there is nothing honest to scope to (a URL
that will not parse leaves the bare tool). A UI that renders the suggestion
should read whichever narrower is there rather than expect C<under>.

=head2 Per-agent elicitation

C<MCP::Client> takes B<one> C<on-elicit> hook, which is a problem the moment a
fleet of agents shares a client: the server's question goes to whichever
policy's C<elicit-hook> was wired at construction, which is rarely the agent
whose call provoked it. Build the children with C<< :claim-elicits >> and each
one answers its own:

=begin code :lang<raku>
my $child = MCP::Client::Policy.new(
	:$provider, on-ask => &ask-in-this-pane, :claim-elicits,
);
=end code

While a claiming policy is forwarding a batch, any elicitation those calls
provoke is put to B<that> policy's C<&on-ask>, as a C<server-elicit>, under
B<that> policy's C<ask-lock> — whichever policy the host wired. The request hash
is unchanged: the callback answering it is already the claimant's own, which is
the only badge a UI needs. Nothing else moves; permission prompts were always
asked by the policy deciding the call.

This works because elicitation is fulfilled on the thread that made the call —
C<MCP::Client> answers an input-required round inline, before C<call-tool>
returns — so the claim travels as a dynamic variable down the forwarding stack.
Three things therefore fall back to the wired policy, which is exactly the
behaviour of every host written before this existed:

=item a call from a policy that did not claim;
=item a claimant with no C<&on-ask> — a headless child does not get to answer by
      declining on behalf of a human somebody else has;
=item a provider that fulfils elicitations on some other thread than the one
      that called it. No provider in this distribution does.

Stacked policies do not fight over a question: the outermost claim wins, because
the call entered through the agent whose batch it is.

=head2 Never throws

C<execute-tool-calls> keeps C<MCP::Client>'s promise exactly: a malformed call,
a denied call, a callback that blew up, a provider that died — each is one
C<is_error> result in the caller's own order, and the calls around it are
unaffected. C<tools-for-llm> keeps the deliberate asymmetry too: a provider
that cannot list its tools throws, because silently publishing a shorter
catalogue leaves a model wondering where a capability went.

=head2 Where in the stack, and what a rule name means

Rules name tools B<as this policy sees them>, which is not always as the model
sees them. A registry strips its prefix before passing a call on, so a policy
B<under> a registry sees C<read> where a policy B<over> the same registry sees
C<fs_read>. Same for C<roots> keys. Getting this wrong is silent: no rule ever
matches, the engine falls through to C<ask>, and every call goes to the human.
If everything is suddenly asking, this is why.

The other composers in this distribution are written to sit B<below> a policy,
in this order:

=begin code :lang<raku>
Policy( Reasons( Leases( Registry ) ) )
=end code

L<MCP::Client::Reasons|lib/MCP/Client/Reasons.rakumod> gives every tool an
optional C<reason> parameter and deletes it again before the call is forwarded.
It goes directly under the policy so that the C<&on-ask> request still carries
the model's sentence — a UI renders it beside the arguments, never instead of
them, and no rule, floor or classifier ever reads it.

L<MCP::Client::Leases|lib/MCP/Client/Leases.rakumod> goes further down still,
so that permission is resolved before a lease is consumed and a re-asked call
cannot walk around one.

=head1 EXAMPLES

Headless, with no human anywhere — a batch job, a CI run. Wire no callback and
anything not explicitly allowed is refused with a message saying so:

=begin code :lang<raku>
my $policy = MCP::Client::Policy.new(
	provider => $mcp,
	rules    => MCP::Client::Policy.default-rules,   # the read-only tools, and user_ask
);

say $policy.interactive;   # False

$policy.execute-tool-calls([
	{ id => '1', function => { name => 'fs_write', arguments => '{"path":"x"}' } },
]);
# ({ role => 'tool', tool_call_id => '1', is_error => True,
#    content => "Permission required: 'fs_write' needs approval, but ..." },)
=end code

The interactive case, with the server's own questions going to the same human
through the same lock. Note the forward declaration: the client needs the hook
at construction and the policy needs the client, so one of the two has to be
named before it exists:

=begin code :lang<raku>
my $policy;
my $mcp = MCP::Client.connect-stdio(
	command   => 'mcp-filesystem',
	args      => ['/srv'],
	on-elicit => -> %request { $policy.elicit-hook.(%request) },
);
$policy = MCP::Client::Policy.new(:provider($mcp), :&on-ask, roots => { fs => '/srv' });
=end code

Wire C<on-elicit> B<only> when there is somebody to ask: setting it is what
declares the elicitation capability to the server, and a server told it may ask
will ask. C<.interactive> is the guard.

Session grants are plain data, so a UI that wants "always allow" to survive a
restart persists them and hands them back:

=begin code :lang<raku>
spurt 'grants.json', to-json($policy.grants);
# ... next run ...
my $policy = MCP::Client::Policy.new(
	:$provider, :&on-ask, grants => from-json(slurp 'grants.json'),
);
=end code

C<&on-grant> says B<when> to do that, rather than leaving a host to poll
C<.grants> or to guess that an C<always-> answer it saw go past has landed. It
is handed the whole list, already copied, the moment the grant is made — before
the call that provoked it has even been decided, so an engine that mirrors
grants into a session sees them in time for the next call in the same batch:

=begin code :lang<raku>
my $policy = MCP::Client::Policy.new(
	:$provider, :&on-ask,
	on-grant => -> @grants { $session.remember-grants(@grants) },
);
=end code

Like C<&on-ask>, it is a leaf: it runs on the thread deciding the call, so
collect what you need and return.

A fleet — a parent agent and the children it spawned, each with its own policy
— wants B<one> grant set between them, or the human answers the same question
once per child. Hand them all the same
L<MCP::Client::Policy::Grants|lib/MCP/Client/Policy/Grants.rakumod> and they
have it:

=begin code :lang<raku>
my $grants = MCP::Client::Policy::Grants.new(grants => $session.grants);

my $parent = MCP::Client::Policy.new(:$provider, :&on-ask, grants-store => $grants);
my $child  = MCP::Client::Policy.new(:$provider, :&on-ask, grants-store => $grants);
=end code

With a store wired, an C<always-> answer is written to the store instead of to
the policy that asked, and every policy reads the store on B<every> decision —
so a grant made through the parent binds a child that started before it and a
child started after it alike. C<.grants> then renders the B<effective> set (this
policy's own grants, then the book), which is what C<&on-grant> is handed and
what a session should persist. Seed a resumed session into the store rather than
into C<grants>, so a rule is not counted twice.

None of this widens anything: grants are still consulted only once the static
rules have said C<ask>, so a shared grant cannot overrule a C<deny> rule or the
danger floor, and a deny grant still beats an allow grant.

Stacked, with a rule set at each layer — the outer policy speaks the model's
names, the inner one speaks the server's:

=begin code :lang<raku>
my $registry = MCP::Client::Registry.new;
$registry.add(
	MCP::Client::Policy.new(provider => $fs-server, rules => [{ tool => 'delete', decision => 'deny' },]),
	prefix => 'fs',
);

my $outer = MCP::Client::Policy.new(
	provider => $registry,
	rules    => [{ tool => 'fs_write', decision => 'ask' },],
	:&on-ask,
);
=end code

=end pod

use JSON::Fast;

use MCP::Client::Exceptions;
use MCP::Client::Policy::Rules;
use MCP::Client::Policy::Grants;

unit class MCP::Client::Policy;

# Everything .new accepts. Named rather than inferred so that a typo -- `rule`
# for `rules`, `root` for `roots` -- is an error at construction instead of a
# policy that silently has no rules and therefore asks about everything.
my constant OPTIONS =
	<provider rules grants grants-store roots path-params command-params checks on-ask on-grant
	 filter-tools ask-lock claim-elicits>.Set;

has $.provider is required;
has &.on-ask;

#| Called with the whole grant list, as C<.grants> renders it, every time an
#| C<always-allow> or C<always-deny> answer adds one — so a host that persists
#| grants, or mirrors them into a session log, hears about it the moment the
#| human says "always" rather than after the batch:
#|
#|   on-grant => -> @grants { spurt 'grants.json', to-json(@grants) },
#|
#| The list is a fresh plain-data deep copy, safe to keep and to edit. It is
#| the grants B<including> the new one, in the order they were made, because a
#| consumer almost always wants the whole set rather than a diff to apply.
#|
#| Called after the policy's own lock is released and outside C<&.on-ask>'s, but
#| still on the thread that is deciding the call — so it is a B<leaf>, exactly as
#| C<&.on-ask> is. Do not re-enter the policy from it (dispatching a tool call,
#| asking another question): the call it belongs to has not been decided yet, and
#| the batch behind it is waiting. A hook that throws is swallowed — a grant that
#| has been made cannot be un-made by a listener that fell over.
has &.on-grant;

#| The shared grant book, if this policy has been given one: an
#| L<MCP::Client::Policy::Grants|lib/MCP/Client/Policy/Grants.rakumod> that any
#| number of policies consult and any of them can add to. With one wired, an
#| C<always-> answer is written B<there> rather than here, and every sharer is
#| bound by it from its very next decision. Undefined when the policy keeps its
#| grants to itself.
has $.grants-store;

has Bool:D $.filter-tools = True;

#| The lock every question is asked under. One human, one question at a time —
#| shared between permission prompts and the server elicitations that
#| C<elicit-hook> forwards. Pass your own to share it with something else.
has Lock:D $.ask-lock .= new;

#| Opt in to claiming the server elicitations this policy's own calls provoke.
#| While a batch from B<this> policy is being forwarded, a server question one of
#| those calls raises is answered by B<this> policy's C<&on-ask> — as a
#| C<server-elicit>, under this policy's C<ask-lock> — whichever policy's
#| C<elicit-hook> the host happened to wire into C<MCP::Client>. That is what
#| lets a fleet of children share one client and still each answer their own
#| server's questions.
#|
#| Off by default: an unclaimed elicitation is answered by the wired policy,
#| exactly as it always was. See "Per-agent elicitation" in the description for
#| the contract and for what falls back to the wired policy.
has Bool:D $.claim-elicits = False;

has Lock $!lock .= new;
has      @!rules;
has      @!grants;
has      %!roots;
has      %!path-params;
has      %!command-params;
has      %!checks;

submethod TWEAK(
	:$provider, :$rules, :$grants, :$grants-store, :$roots, :$path-params, :$command-params,
	:$checks, :&on-ask, :&on-grant, :$filter-tools, :$ask-lock, :$claim-elicits,
	*%unknown
) {
	my @unknown = %unknown.keys.grep({ !OPTIONS{$_} }).sort;
	die X::MCP::Client.new(
		detail => "unknown option(s) for a policy: '{@unknown.join(q{', '})}'; a policy is made of "
			~ OPTIONS.keys.sort.join(', '),
	) if @unknown;

	# .can rather than .^can, and structural rather than nominal: the same
	# contract MCP::Client::Registry.add checks, for the same reason -- an
	# MCP::Client, an MCP::Server and a registry share no ancestor and should
	# not have to.
	die X::MCP::Client.new(
		detail => 'cannot build a policy over '
			~ ($!provider.defined ?? 'a ' ~ $!provider.^name !! 'the ' ~ $!provider.^name ~ ' type object')
			~ ': a tool provider must be a defined object with both a tools-for-llm and an '
			~ 'execute-tool-calls method',
	) unless $!provider.defined && provider-shaped($!provider);

	# Prose rather than a type constraint on the attribute: a caller who passed
	# the grant *list* where the store goes should be told which of the two this
	# option wants, not handed a binding failure.
	die X::MCP::Client.new(
		detail => 'the grants-store of a policy must be an MCP::Client::Policy::Grants, not '
			~ ($grants-store.defined
				?? 'a ' ~ $grants-store.^name
				!! 'the ' ~ $grants-store.^name ~ ' type object'),
	) unless $grants-store === Any || $grants-store ~~ MCP::Client::Policy::Grants:D;

	@!rules = validate-rules($rules, what => 'policy rule');
	@!grants = validate-rules($grants, what => 'policy grant');
	%!roots = validate-roots($roots);
	%!path-params = validate-path-params($path-params);
	%!command-params = validate-command-params($command-params);

	# The checks are code the policy supplies for a rule's `check` predicate to
	# name (the danger floor's target analysis). Not plain data, so not
	# serialised and not returned by an accessor -- a rule only ever names one.
	if $checks.defined {
		die X::MCP::Client.new(
			detail => 'the policy checks must be an object of check name to callable, not a '
				~ $checks.^name,
		) unless $checks ~~ Associative;
		for $checks.Hash.kv -> $name, $fn {
			die X::MCP::Client.new(
				detail => "the policy check '$name' must be a callable",
			) unless $fn ~~ Callable;
			%!checks{$name} = $fn;
		}
	}
}

#| The rules this policy was built with, as a deep plain-data copy: safe to
#| serialise, and safe to hand to a UI that edits what it is given.
method rules(--> List:D) {
	$!lock.protect: { @!rules.map({ plain-copy($_) }).List };
}

#| Swap the whole rule set atomically — the seam a preset switch rides on. The
#| new rules are validated first (a bad set throws and the old rules stand), then
#| installed under the lock, so a call deciding concurrently sees either the old
#| set or the new one, never a half-applied mix. Grants, roots, path-params,
#| command-params and checks are untouched.
#|
#| The catalogue (C<tools-for-llm>) reflects the new rules from the next time it
#| is fetched — a consumer that lists tools once per run therefore sees the
#| change at the next run boundary, which is the intended granularity.
method replace-rules(@new-rules --> Nil) {
	my @validated = validate-rules(@new-rules, what => 'policy rule');
	$!lock.protect: { @!rules = @validated };
	Nil;
}

#| The session grants — the C<always-allow> and C<always-deny> answers in force
#| — in the order they were made, as a deep plain-data copy. Persist them and
#| pass them back as C<grants> to carry a session over.
#|
#| This is the B<effective> set: the grants this policy was built with, followed
#| by everything in the shared C<grants-store>, if it has one. It is exactly
#| what a call is decided against and exactly what C<&.on-grant> is handed, so a
#| host that persists one and resumes from it resumes what was really in force.
#|
#| With a store wired, seed the session's remembered grants into the B<store>
#| rather than into C<grants>: putting the same rules in both makes them appear
#| twice here (harmless to decide against — a repeated rule decides the same
#| call the same way — but noise in anything that persists this list).
method grants(--> List:D) {
	my @mine = $!lock.protect: { @!grants.map({ plain-copy($_) }) };
	return @mine.List without $!grants-store;
	(|@mine, |$!grants-store.list).List;
}

#| The tool-name-prefix to directory table, as a copy.
method roots(--> Hash:D) {
	%!roots.Hash;
}

#| The per-tool overrides of the C<path>/C<from>/C<to> convention, as a copy.
method path-params(--> Hash:D) {
	%!path-params.map({ $_.key => $_.value.List }).Hash;
}

#| The per-tool overrides of the C<command>/C<args> convention — which
#| parameters name a call's program and argv — as a copy.
method command-params(--> Hash:D) {
	%!command-params.map({ $_.key => $_.value.Hash }).Hash;
}

#| Whether there is anybody to ask. False means every C<ask> outcome is a
#| refusal — and means C<MCP::Client>'s C<on-elicit> must be left unwired, since
#| wiring it is what tells a server it may ask questions.
method interactive(--> Bool:D) {
	so &!on-ask;
}

#| The starting rules for a coding agent: the C<MCP::Server::Tool::FileSystem>
#| pack's read-only tools, C<user_ask>, and the two lease tools.
#|
#| C<user_ask> is on the list because asking the human is inherently consented
#| to — the elicitation UI I<is> the permission prompt, and the human answers or
#| declines there. Without it, a model wanting to ask a question would first
#| trigger a permission prompt asking whether it may ask a question.
#|
#| C<lock_acquire> and C<lock_release> are on it for the same reason: they are
#| C<MCP::Client::Leases>'s bookkeeping over its own table, they change nothing
#| a human owns, and asking permission to take an advisory lock is pure
#| friction — the answer is always yes, and a model that has just been told to
#| lock before it writes would stop at a prompt to do so. With no lease layer
#| stacked, the two names simply never appear.
#|
#| There is deliberately no C<< { tool => '*', decision => 'ask' } >> catch-all:
#| the engine already asks about anything no rule matched, and a catch-all would
#| suppress the session grants (see the description).
#|
#| The names assume the packs' default prefixes and a policy sitting directly
#| over the server that publishes them.
method default-rules(--> List:D) {
	(
		{ tool => 'fs_read', decision => 'allow' },
		{ tool => 'fs_list', decision => 'allow' },
		{ tool => 'fs_glob', decision => 'allow' },
		{ tool => 'fs_stat', decision => 'allow' },
		{ tool => 'fs_grep', decision => 'allow' },
		{ tool => 'fs_map', decision => 'allow' },
		{ tool => 'user_ask', decision => 'allow' },
		{ tool => 'lock_acquire', decision => 'allow' },
		{ tool => 'lock_release', decision => 'allow' },
	).List;
}

# === The bridge ===

#| The provider's tool declarations, with the tools that a bare (no C<under>)
#| static deny rule refuses left out — a model that cannot see a tool does not
#| spend a turn discovering it may not use it. C<filter-tools => False> publishes
#| the catalogue unabridged.
#|
#| Session grants do not change the catalogue: a tool list is normally fetched
#| once, and a list that shrank halfway through a conversation would be stranger
#| than one that did not.
#|
#| Throws whatever the provider throws while listing.
method tools-for-llm(--> List) {
	my @published = $!provider.tools-for-llm.list;
	return @published.List unless $!filter-tools;

	# Only a blanket deny hides its tool. A deny that narrows by path, by host or
	# by command still permits the tool for the calls it does not refuse, so the
	# model must be able to see it. Snapshot under the lock so a concurrent
	# replace-rules cannot be observed half-applied.
	my @rules = $!lock.protect: { @!rules.List };
	my @hiding = @rules.grep({
		$_<decision> eq 'deny'
			&& !($_<under>:exists)
			&& !($_<host>:exists)
			&& !($_<command>:exists)
			&& !($_<args>:exists)
			&& !($_<args-any>:exists)
			&& !($_<check>:exists)
	});
	return @published.List unless @hiding;

	@published.grep({ !hidden-by(@hiding, $_) }).List;
}

#| Evaluate every call, forward the ones that are allowed as a single batch,
#| and return one result per call in the caller's order.
#|
#| B<Never throws.> A refusal, a malformed call, a callback that threw and a
#| provider that died all come back as C<is_error> results.
method execute-tool-calls(@tool-calls --> List) {
	# Snapshot the rules once, under the lock, so the whole batch is decided
	# against one coherent rule set even if a preset switch lands mid-batch.
	my @rules = $!lock.protect: { @!rules.map({ plain-copy($_) }).List };
	my @results;
	my @forward;

	for @tool-calls.kv -> $index, $call {
		my $function = $call ~~ Associative ?? $call<function> !! Any;
		my $id = $call ~~ Associative ?? ($call<id> // '') !! '';

		# A call the policy cannot read is a call the policy cannot vouch for,
		# so it is refused here rather than forwarded to find out.
		unless $function ~~ Associative && $function<name> ~~ Str:D {
			@results[$index] = error-result(
				$id,
				'Malformed tool call: expected an object with a function name, '
					~ 'which the policy needs in order to have an opinion about it',
			);
			next;
		}

		my $name = $function<name>;
		my %outcome = self!decide($name, $function<arguments>, $call, @rules);

		if %outcome<decision> eq 'allow' {
			# The original call hash, not a copy: whatever the model sent, the
			# provider sees byte for byte, so wrapping a provider in a policy
			# cannot change what an allowed call does.
			@forward.push: %( :$index, :$id, call => $call );
		}
		else {
			# The fallback is belt and braces: every refusal below builds a
			# message, and a future one that forgot must not turn "never throws"
			# into a type error at the caller.
			@results[$index] = error-result($id, %outcome<message> // "Permission denied: '$name'");
		}
	}

	# WHO a server question raised by this batch belongs to. Read here, in the
	# enclosing scope, and installed below: a dynamic variable cannot be looked up
	# and declared in one scope, and looking it up on the right of its own
	# declaration would only ever find the fresh container. An outer claim wins,
	# because the call entered through the outermost claimant -- a stacked policy
	# does not take a question away from the agent whose batch this is.
	my $claimant = $*MCP-CLIENT-ELICIT-POLICY // ($!claim-elicits ?? self !! Nil);

	if @forward {
		my @calls = @forward.map({ $_<call> }).List;

		# A dynamic variable rather than an argument, because elicitation
		# fulfilment runs on the thread that made the call -- MCP::Client answers
		# an input-required round inline, before it returns -- so this frame is
		# still on the stack when &on-elicit fires and elicit-hook can find the
		# claim by walking up to it.
		my $*MCP-CLIENT-ELICIT-POLICY = $claimant;

		my @answers;
		my $failure;
		{
			CATCH { default { $failure = $_ } }
			@answers = $!provider.execute-tool-calls(@calls).list;
		}

		for @forward.kv -> $at, %item {
			@results[%item<index>] = $failure.defined
				?? error-result(%item<id>, "The tool provider failed: {$failure.message}")
				!! normalized-result(@answers[$at], %item<id>);
		}
	}

	@results.List;
}

#| A closure for C<MCP::Client.new(:on-elicit(...))>: it forwards the server's
#| question to C<&on-ask> as a C<server-elicit>, under the same lock permission
#| prompts are asked under.
#|
#| The question goes to whichever policy B<claimed> it — the one whose forwarded
#| batch provoked it, if that policy was built with C<< :claim-elicits >> — and
#| otherwise to this one, the policy the client was wired to. See "Per-agent
#| elicitation" in the description.
#|
#| With no callback wired — or with one that throws, or answers with something
#| that is not an C<ElicitResult> — the server is declined. Declining is an
#| ordinary answer in the protocol, and one the server is required to handle.
method elicit-hook(--> Callable:D) {
	-> %request {
		# Whose question this is. A claimant that cannot ask anybody is no use
		# here, so a headless claimant hands the question back to the policy the
		# host wired -- which may have a human even though the child does not.
		my $claimant = $*MCP-CLIENT-ELICIT-POLICY // Nil;
		my $target = $claimant ~~ MCP::Client::Policy:D && $claimant.interactive
			?? $claimant
			!! self;

		# Not annotated with who claimed it: the request is the server's question
		# as it stands, and the callback answering it is already the claimant's
		# own, which is the only badge a UI needs.
		$target!answer-elicit(%request);
	};
}

# One server elicitation, put to this policy's human under this policy's lock.
# Split out of elicit-hook so that a claiming policy can be handed the question
# the wired policy was asked for -- a private method on another instance of the
# same class, which is the least public seam that will carry it.
method !answer-elicit(%request --> Hash:D) {
	my $answer;

	# A guard rather than an early return: there are two ways of having no answer
	# -- no callback at all, and a callback that threw -- and both leave $answer
	# undefined and fall through to the decline below.
	if &!on-ask.defined {
		$!ask-lock.protect: {
			CATCH { default { $answer = Nil } }
			$answer = &!on-ask({ kind => 'server-elicit', request => plain-copy(%request) });
		}
	}

	$answer ~~ Associative ?? $answer.Hash !! { action => 'decline' };
}

# === Deciding ===

# One call, from its raw arguments to allow-or-refuse. The refusal message is
# built here rather than at the call site so that every way of saying no reads
# like the others.
method !decide(Str:D $name, $raw-arguments, $call, @rules --> Hash:D) {
	my $arguments = parse-arguments($raw-arguments);

	my %verdict = evaluate(
		@rules, $name, $arguments,
		roots => %!roots, path-params => %!path-params,
		command-params => %!command-params, checks => %!checks,
	);

	# Grants are consulted only once the static rules have said "ask": a rule
	# that asks is a standing instruction to keep asking.
	if %verdict<decision> eq 'ask' {
		# self.grants, not a snapshot taken at construction: with a shared store
		# wired, a grant another agent's human made a moment ago is in force for
		# this call.
		my %granted = evaluate(
			self.grants, $name, $arguments,
			roots => %!roots, path-params => %!path-params,
			command-params => %!command-params, checks => %!checks,
		);
		%verdict = %granted if %granted<rule>.defined;
	}

	given %verdict<decision> {
		when 'allow' { return %( decision => 'allow' ) }
		when 'deny'  { return %( decision => 'deny', message => refusal-by-rule($name, %verdict) ) }
	}

	self!ask($name, $arguments, $call, %verdict);
}

#| The session grants, consulted directly: what a host that asks the human
#| B<itself> — outside this policy's own prompt, inside its own bracket of locks
#| — calls before it puts the question, so that a question the human has already
#| answered with "always" is never put again.
#|
#| Evaluates B<only> the effective grants — never the static rules, because a
#| rule that allowed or denied decided the call long before anything asked —
#| with this policy's roots, path-params, command-params and checks, exactly as a
#| real decision would.
#|
#| Answers in the shape of an C<&on-ask> answer, so a callback can return it
#| verbatim:
#|
#|   a grant that allows  ->  { action => 'allow-once', rule, reason }
#|   a grant that denies  ->  { action => 'deny-once',  rule, reason, message }
#|   no grant decides     ->  Hash    # the type object; test it with `with`
#|
#| The C<message> of a denial is the same rule-shaped refusal a static deny
#| produces, so a host that hands it back gets the phrasing the policy would
#| have used itself. C<reason> is C<'rule'> or C<'unevaluable-path'>, as in the
#| ask request.
#|
#| B<Never throws>, and B<never touches the ask-lock> — arguments that will not
#| parse are treated exactly as a real decision treats them (a grant naming a
#| bare tool still decides; a path-scoped one cannot match), so it is safe to
#| call from inside an C<&on-ask> callback that this or any other policy is
#| holding its ask-lock around. It reads the policy's own state under the
#| policy's own leaf lock, which is the order every other path takes them in.
method grant-decision(Str:D $tool, $arguments --> Hash) {
	my $parsed = parse-arguments($arguments);
	my %granted = evaluate(
		self.grants, $tool, $parsed,
		roots => %!roots, path-params => %!path-params,
		command-params => %!command-params, checks => %!checks,
	);
	return Hash unless %granted<rule>.defined;

	given %granted<decision> {
		when 'allow' {
			%(
				action => 'allow-once',
				rule => plain-copy(%granted<rule>),
				reason => (%granted<reason> // Str),
			);
		}
		when 'deny' {
			%(
				action => 'deny-once',
				rule => plain-copy(%granted<rule>),
				reason => (%granted<reason> // Str),
				message => refusal-by-rule($tool, %granted),
			);
		}
		# A grant whose decision is `ask` decides nothing: it is a standing
		# instruction to keep asking, and the host should go on and ask.
		default { Hash }
	}
}

# The human, or the absence of one.
method !ask(Str:D $name, $arguments, $call, %verdict --> Hash:D) {
	without &!on-ask {
		return %(
			decision => 'deny',
			message => "Permission required: '$name' needs approval, but this agent is running "
				~ 'without a permission prompt, so the call was refused'
				~ path-note(%verdict),
		);
	}

	my %request =
		kind       => 'permission',
		tool       => $name,
		arguments  => ($arguments ~~ Associative ?? plain-copy($arguments) !! {}),
		call       => plain-copy($call),
		rule       => (%verdict<rule>.defined ?? plain-copy(%verdict<rule>) !! Hash),
		reason     => %verdict<reason>,
		paths      => %verdict<paths>.List,
		suggestion => plain-copy(%verdict<suggestion>),
	;

	my $answer;
	my $threw;
	my $action = '';
	my %granted;
	my %kept;
	$!ask-lock.protect: {
		# The re-check. N agents queued on this lock behind an "always" answer
		# must not each re-ask the question it settled, so the effective grants
		# are read again here, once the queue has been survived, and whichever
		# waiter finds one answers its own call silently -- the grant path of
		# !decide, moved inside the lock. No observer fires and nothing new is
		# remembered: deciding by a grant never was an event.
		#
		# Sound for the FIRST waiter and not merely for the rest of the queue,
		# because the answer below is written down before this lock is released:
		# a grant is visible to self.grants strictly before any waiter can wake
		# and read it. Without that ordering the waiter next in line would race
		# the answering thread's write and sometimes re-ask.
		#
		# This nests $!lock (self.grants, !remember) inside the ask-lock, which
		# is safe because nothing anywhere takes them the other way round:
		# elicit-hook takes only the ask-lock, the shared grant book is a leaf
		# with a lock of its own, and every path that touches $!lock either has
		# the ask-lock or wants nothing else.
		%granted = evaluate(
			self.grants, $name, $arguments,
			roots => %!roots, path-params => %!path-params,
			command-params => %!command-params, checks => %!checks,
		);

		# A grant that says `ask` settles nothing, and neither does no grant at
		# all: both fall through to the human, who is now next in the queue.
		%granted = () unless %granted<rule>.defined
			&& %granted<decision> eq 'allow' | 'deny';

		unless %granted {
			CATCH { default { $threw = $_ } }
			$answer = &!on-ask(%request);
			$action = $answer ~~ Associative ?? ($answer<action> // '') !! '';

			# Still holding the lock: an "always" answer is a grant the moment
			# the human gives it, and the queue behind this call is entitled to
			# find it there. A callback that threw never reaches this line --
			# the CATCH above exits the block with it -- and a rule that will
			# not validate is caught inside !remember, so an answer that cannot
			# be kept refuses its call exactly as it always did.
			if $action eq 'always-allow' | 'always-deny' {
				%kept = self!remember(
					$answer, %request, $action eq 'always-allow' ?? 'allow' !! 'deny',
				);
			}
		}
	}

	if %granted {
		return %granted<decision> eq 'allow'
			?? %( decision => 'allow' )
			!! %( decision => 'deny', message => refusal-by-rule($name, %granted) );
	}

	if $threw.defined {
		return %(
			decision => 'deny',
			message => "Permission denied: the permission prompt for '$name' failed "
				~ "({$threw.message.lines.head // 'no reason given'}), so the call was refused",
		);
	}

	# The announcement, once the lock is out of the way but before the call that
	# provoked the grant is decided -- which is the contract &.on-grant documents.
	self!announce-grants(%kept<snapshot>) if %kept<ok>;

	given $action {
		when 'allow-once' {
			%( decision => 'allow' );
		}
		when 'deny-once' {
			%( decision => 'deny', message => "Permission denied: the user refused '$name'" );
		}
		when 'always-allow' | 'always-deny' {
			# Already remembered, under the lock, and already announced.
			my $wanted = $action eq 'always-allow' ?? 'allow' !! 'deny';

			if %kept<ok> {
				$wanted eq 'allow'
					?? %( decision => 'allow' )
					!! %(
						decision => 'deny',
						message => "Permission denied: the user refused '$name', and every call "
							~ "matching {%kept<rules>.map({ q{'} ~ rule-text($_) ~ q{'} }).join(', ')} "
							~ 'from now on',
					);
			}
			else {
				%(
					decision => 'deny',
					message => "Permission denied: the permission prompt for '$name' asked to "
						~ "remember something that is not a usable rule ({%kept<why>}), so the "
						~ 'call was refused',
				);
			}
		}
		default {
			%(
				decision => 'deny',
				message => "Permission denied: the permission prompt for '$name' answered with "
					~ ($action.chars
						?? "an action nobody understands ('$action')"
						!! 'something that is not an answer')
					~ ', so the call was refused',
			);
		}
	}
}

# Turn an always-answer into session grants and append them. Appended
# immediately, so a later call in the same batch is decided by a grant the human
# made two calls ago -- which is the whole point of saying "always" to a model
# that asked for six things at once.
#
# Called with the ask-lock held, and that is not incidental: the grant has to be
# visible to self.grants before the next waiter can wake and re-check, or the
# question the human has just answered gets put to them again. Announcing it is
# somebody else's code and therefore somebody else's problem, so that half is
# !announce-grants, called once the lock is released. Answers
# { ok => True, rules => [...], snapshot => [...] } or { ok => False, why => ... },
# and never throws either way.
method !remember($answer, %request, Str:D $decision --> Hash:D) {
	my %wanted = self!wanted-grants($answer, %request, $decision);
	return %wanted unless %wanted<ok>;
	my @rules = %wanted<rules>.list;

	my @snapshot;
	my $failed;
	{
		# Belt and braces: every rule here has already been through the
		# validator, so the store cannot refuse them -- and "never throws" is
		# not a promise to keep by assumption.
		CATCH {
			default {
				$failed = $_ ~~ X::MCP::Client
					?? ($_.detail // $_.message)
					!! ($_.message.lines.head // 'it could not be kept');
			}
		}

		if $!grants-store.defined {
			# Written to the book, not to this policy: the grant belongs to the
			# session, and every policy sharing the book is bound by it from its
			# next decision. The effective list -- what .grants renders, and what
			# on-grant is owed -- is this policy's own grants and then the book.
			my @book = $!grants-store.add(@rules);
			my @mine = $!lock.protect: { @!grants.map({ plain-copy($_) }) };
			@snapshot = (|@mine, |@book);
		}
		else {
			$!lock.protect: {
				@!grants.append: @rules;
				# Copied under the lock so the snapshot is of the list as it
				# stood when this grant landed, whatever another thread's batch
				# does next.
				@snapshot = @!grants.map({ plain-copy($_) });
			}
		}
	}

	return %( ok => False, why => $failed ) if $failed.defined;

	%( ok => True, rules => @rules.List, snapshot => @snapshot.List );
}

# Tell &.on-grant about the grant that has just been made. Outside the ask-lock,
# and after it: the hook is somebody else's code, and one that took a while
# (writing grants.json, say) would otherwise hold every other agent's question
# up behind it -- including the waiters the grant has just decided. A hook that
# throws changes nothing -- the grant is already made, and refusing the call over
# a failed listener would be a worse answer than a call that went through
# unannounced.
#
# One firing per answer, not per rule: a UI that offered "allow edits and new
# directories here" asked one question and got one answer, and a host persisting
# the list wants to write it once.
method !announce-grants(@snapshot --> Nil) {
	if &!on-grant.defined {
		CATCH { default { } }
		&!on-grant(@snapshot.List);
	}
	Nil;
}

# What an always-answer asked to be remembered, validated: one rule, several, or
# the suggestion it was offered. Answers { ok => True, rules => [...] } or
# { ok => False, why => '...' }, and refuses the whole answer if any one rule in
# it is unusable -- half a grant is not what the human said yes to.
method !wanted-grants($answer, %request, Str:D $decision --> Hash:D) {
	my $one = $answer ~~ Associative ?? $answer<rule> !! Any;
	my $many = $answer ~~ Associative ?? $answer<rules> !! Any;

	if $one.defined && $many.defined {
		return %(
			ok => False,
			why => 'it named both a rule and a list of rules, and only one of the two can be '
				~ 'what it meant',
		);
	}

	my @wanted;
	if $many.defined {
		return %(
			ok => False,
			why => "its rules are a {$many.^name} rather than a list of rule objects",
		) unless $many ~~ Positional;

		my @given = $many.list;
		return %( ok => False, why => 'its list of rules is empty' ) unless @given;

		# The decision comes from the action, exactly as it does for a single
		# rule: a UI says what the human clicked, not what it means.
		@wanted = @given.map({
			$_ ~~ Associative
				?? do { my %rule = $_.Hash; %rule<decision> = $decision; %rule }
				!! $_
		});
	}
	else {
		# An explicit rule is taken as written -- a UI that deliberately narrows
		# the suggestion to a bare tool must not have the suggestion's `under`
		# put back.
		my %rule = $one ~~ Associative ?? $one.Hash !! plain-copy(%request<suggestion>);
		%rule<decision> = $decision;
		@wanted = %rule,;
	}

	my @rules;
	my $why;
	{
		CATCH {
			default {
				$why = $_ ~~ X::MCP::Client
					?? ($_.detail // $_.message)
					!! ($_.message.lines.head // 'it could not be read');
			}
		}
		@rules = @wanted.map({ validate-rule($_, what => 'session grant') });
	}

	$why.defined ?? %( ok => False, :$why ) !! %( ok => True, rules => @rules.List );
}

# === Helpers ===

# Whether an object implements the bridge pair: the whole of the provider
# contract, and the same test MCP::Client::Registry makes.
my sub provider-shaped($provider --> Bool:D) {
	so $provider.can('tools-for-llm') && $provider.can('execute-tool-calls');
}

# The arguments of a call, parsed exactly as MCP::Client's own bridge parses
# them (Client.rakumod, !execute-one) and as MCP::Server's does: a hash is a
# hash, an empty or whitespace-only string is a call with no arguments, and
# anything else is JSON. The duplication is deliberate -- the policy has to know
# what a call means *before* the provider is allowed to find out -- and t/14
# pins the two together by running the same argument shapes through both.
#
# Anything that will not parse comes back undefined, which the engine reads as
# "every path predicate is unknown".
my sub parse-arguments($raw) {
	my $args = $raw // {};
	return $args.Hash if $args ~~ Associative;
	return {} if $args.Str.trim eq '';

	my $parsed;
	{
		CATCH { default { $parsed = Nil } }
		$parsed = from-json($args.Str);
	}

	$parsed ~~ Associative ?? $parsed.Hash !! Any;
}

# A rule as a human reads it back. The narrowers are named in the order they
# read in -- "deny web_fetch on evil.com" -- so a refusal says what the rule was
# about and not merely which tool it was about.
my sub rule-text(%rule --> Str:D) {
	my $text = "{%rule<decision>} {%rule<tool>}";
	$text ~= " under {%rule<under>}" if %rule<under>:exists;
	$text ~= " on {%rule<host>}" if %rule<host>:exists;
	$text;
}

my sub path-note(%verdict --> Str:D) {
	my @paths = %verdict<paths>.list;
	return '' unless @paths;
	" (paths: {@paths.join(', ')})";
}

my sub refusal-by-rule(Str:D $name, %verdict --> Str:D) {
	"Permission denied by policy: '$name' matched the rule '{rule-text(%verdict<rule>)}'"
		~ (%verdict<reason> eq 'unevaluable-path'
			?? ", which could not be ruled out because the call's locations cannot be checked "
				~ 'without resolving them on the server'
			!! '')
		~ path-note(%verdict);
}

# Whether a published declaration names a tool a bare deny rule refuses. A
# declaration with no function name is never hidden: there is nothing to match,
# and dropping it would conceal that a provider published something odd.
my sub hidden-by(@rules, $tool --> Bool:D) {
	return False unless $tool ~~ Associative;
	my $function = $tool<function>;
	return False unless $function ~~ Associative && $function<name> ~~ Str:D;

	so @rules.first({ match-tool($_<tool>, $function<name>) }).defined;
}

# A deep copy of plain data: hashes and lists rebuilt, everything else passed
# through. Snapshots handed to a caller (and payloads handed to a callback) are
# theirs to keep and to edit, and must not be a window onto the policy's own
# state -- or, worse, onto the call that is about to be forwarded.
my sub plain-copy($value) {
	return $value.Hash.map({ $_.key => plain-copy($_.value) }).Hash if $value ~~ Associative;
	return $value.list.map({ plain-copy($_) }).List if $value ~~ Positional;
	$value;
}

my sub error-result($id, Str:D $content --> Hash:D) {
	{
		role => 'tool',
		tool_call_id => $id,
		content => $content,
		is_error => True,
	};
}

# A provider's answer, made safe to hand on: the same normalisation
# MCP::Client::Registry applies, because the caller is owed exactly one
# well-formed result per call however short the provider came up.
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
