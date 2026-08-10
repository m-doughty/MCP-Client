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
=end code

C<rule> defaults to C<suggestion>, and the C<decision> of a remembered rule is
taken from the action rather than from the rule, so a UI need only say what the
human clicked. Anything else — an unknown action, a rule that will not
validate, a callback that throws, no callback at all — is a refusal of B<this
call only>, phrased in a way the model can read and act on.

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

A C<suggestion> is the deepest directory that really contains every path in
the call, so it can be as wide as C<'/'> when nothing narrower is true (an
absolute path with no configured root, for instance). A UI should render the
suggested directory rather than assume it is narrow.

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

unit class MCP::Client::Policy;

# Everything .new accepts. Named rather than inferred so that a typo -- `rule`
# for `rules`, `root` for `roots` -- is an error at construction instead of a
# policy that silently has no rules and therefore asks about everything.
my constant OPTIONS =
	<provider rules grants roots path-params on-ask on-grant filter-tools ask-lock>.Set;

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

has Bool:D $.filter-tools = True;

#| The lock every question is asked under. One human, one question at a time —
#| shared between permission prompts and the server elicitations that
#| C<elicit-hook> forwards. Pass your own to share it with something else.
has Lock:D $.ask-lock .= new;

has Lock $!lock .= new;
has      @!rules;
has      @!grants;
has      %!roots;
has      %!path-params;

submethod TWEAK(
	:$provider, :$rules, :$grants, :$roots, :$path-params,
	:&on-ask, :&on-grant, :$filter-tools, :$ask-lock,
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

	@!rules = validate-rules($rules, what => 'policy rule');
	@!grants = validate-rules($grants, what => 'policy grant');
	%!roots = validate-roots($roots);
	%!path-params = validate-path-params($path-params);
}

#| The rules this policy was built with, as a deep plain-data copy: safe to
#| serialise, and safe to hand to a UI that edits what it is given.
method rules(--> List:D) {
	@!rules.map({ plain-copy($_) }).List;
}

#| The session grants — the C<always-allow> and C<always-deny> answers this
#| policy has been given — in the order they were made, as a deep plain-data
#| copy. Persist them and pass them back as C<grants> to carry a session over.
method grants(--> List:D) {
	$!lock.protect: { @!grants.map({ plain-copy($_) }).List };
}

#| The tool-name-prefix to directory table, as a copy.
method roots(--> Hash:D) {
	%!roots.Hash;
}

#| The per-tool overrides of the C<path>/C<from>/C<to> convention, as a copy.
method path-params(--> Hash:D) {
	%!path-params.map({ $_.key => $_.value.List }).Hash;
}

#| Whether there is anybody to ask. False means every C<ask> outcome is a
#| refusal — and means C<MCP::Client>'s C<on-elicit> must be left unwired, since
#| wiring it is what tells a server it may ask questions.
method interactive(--> Bool:D) {
	so &!on-ask;
}

#| The starting rules for a coding agent: the C<MCP::Server::Tool::FileSystem>
#| pack's read-only tools, and C<user_ask>.
#|
#| C<user_ask> is on the list because asking the human is inherently consented
#| to — the elicitation UI I<is> the permission prompt, and the human answers or
#| declines there. Without it, a model wanting to ask a question would first
#| trigger a permission prompt asking whether it may ask a question.
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
		{ tool => 'user_ask', decision => 'allow' },
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

	my @hiding = @!rules.grep({ $_<decision> eq 'deny' && !($_<under>:exists) });
	return @published.List unless @hiding;

	@published.grep({ !hidden-by(@hiding, $_) }).List;
}

#| Evaluate every call, forward the ones that are allowed as a single batch,
#| and return one result per call in the caller's order.
#|
#| B<Never throws.> A refusal, a malformed call, a callback that threw and a
#| provider that died all come back as C<is_error> results.
method execute-tool-calls(@tool-calls --> List) {
	my @rules = @!rules.map({ plain-copy($_) }).List;
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

	if @forward {
		my @calls = @forward.map({ $_<call> }).List;
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
#| With no callback wired — or with one that throws, or answers with something
#| that is not an C<ElicitResult> — the server is declined. Declining is an
#| ordinary answer in the protocol, and one the server is required to handle.
method elicit-hook(--> Callable:D) {
	-> %request {
		my $answer;

		# `if`, not an early `return`: this closure is a Block, and `return`
		# from one dies rather than exiting it.
		if &!on-ask.defined {
			$!ask-lock.protect: {
				CATCH { default { $answer = Nil } }
				$answer = &!on-ask({ kind => 'server-elicit', request => plain-copy(%request) });
			}
		}

		$answer ~~ Associative ?? $answer.Hash !! { action => 'decline' };
	};
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
	);

	# Grants are consulted only once the static rules have said "ask": a rule
	# that asks is a standing instruction to keep asking.
	if %verdict<decision> eq 'ask' {
		my %granted = evaluate(
			self!grant-snapshot, $name, $arguments,
			roots => %!roots, path-params => %!path-params,
		);
		%verdict = %granted if %granted<rule>.defined;
	}

	given %verdict<decision> {
		when 'allow' { return %( decision => 'allow' ) }
		when 'deny'  { return %( decision => 'deny', message => refusal-by-rule($name, %verdict) ) }
	}

	self!ask($name, $arguments, $call, %verdict);
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
	$!ask-lock.protect: {
		CATCH { default { $threw = $_ } }
		$answer = &!on-ask(%request);
	}

	if $threw.defined {
		return %(
			decision => 'deny',
			message => "Permission denied: the permission prompt for '$name' failed "
				~ "({$threw.message.lines.head // 'no reason given'}), so the call was refused",
		);
	}

	my $action = $answer ~~ Associative ?? ($answer<action> // '') !! '';

	given $action {
		when 'allow-once' {
			%( decision => 'allow' );
		}
		when 'deny-once' {
			%( decision => 'deny', message => "Permission denied: the user refused '$name'" );
		}
		when 'always-allow' | 'always-deny' {
			my $wanted = $action eq 'always-allow' ?? 'allow' !! 'deny';
			my %kept = self!remember($answer, %request, $wanted);

			if %kept<ok> {
				$wanted eq 'allow'
					?? %( decision => 'allow' )
					!! %(
						decision => 'deny',
						message => "Permission denied: the user refused '$name', and every call "
							~ "matching '{rule-text(%kept<rule>)}' from now on",
					);
			}
			else {
				%(
					decision => 'deny',
					message => "Permission denied: the permission prompt for '$name' asked to "
						~ "remember a rule that is not a usable one ({%kept<why>}), so the call "
						~ 'was refused',
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

# Turn an always-answer into a session grant and append it. Appended under the
# lock and immediately, so a later call in the same batch is decided by a grant
# the human made two calls ago -- which is the whole point of saying "always"
# to a model that asked for six things at once.
method !remember($answer, %request, Str:D $decision --> Hash:D) {
	my $given = $answer ~~ Associative ?? $answer<rule> !! Any;

	# An explicit rule is taken as written -- a UI that deliberately narrows the
	# suggestion to a bare tool must not have the suggestion's `under` put back.
	my %wanted = $given ~~ Associative ?? $given.Hash !! plain-copy(%request<suggestion>);
	%wanted<decision> = $decision;

	my %rule;
	my $why;
	{
		CATCH {
			default {
				$why = $_ ~~ X::MCP::Client
					?? ($_.detail // $_.message)
					!! ($_.message.lines.head // 'it could not be read');
			}
		}
		%rule = validate-rule(%wanted, what => 'session grant');
	}

	return %( ok => False, :$why ) if $why.defined;

	my @snapshot;
	$!lock.protect: {
		@!grants.push: %rule;
		# Copied under the lock so the snapshot is of the list as it stood when
		# this grant landed, whatever another thread's batch does next.
		@snapshot = @!grants.map({ plain-copy($_) });
	}

	# Outside the lock, and after it: the hook is somebody else's code, and one
	# that took a while (writing grants.json, say) would otherwise hold every
	# other batch's decisions up behind it. A hook that throws changes nothing --
	# the grant is already made, and refusing the call over a failed listener
	# would be a worse answer than a call that went through unannounced.
	if &!on-grant.defined {
		CATCH { default { } }
		&!on-grant(@snapshot.List);
	}

	%( ok => True, rule => %rule );
}

method !grant-snapshot(--> List:D) {
	$!lock.protect: { @!grants.map({ plain-copy($_) }).List };
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

# A rule as a human reads it back.
my sub rule-text(%rule --> Str:D) {
	%rule<under>:exists
		?? "{%rule<decision>} {%rule<tool>} under {%rule<under>}"
		!! "{%rule<decision>} {%rule<tool>}";
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
