=begin pod

=head1 NAME

MCP::Client::Leases - advisory file leases for concurrent agents over one workspace

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Leases;
use MCP::Client::Leases::Table;
use MCP::Client::Policy;

# One table for the workspace, made by whatever owns the agents.
my $table = MCP::Client::Leases::Table.new;

# One composer per agent, under the policy: permission is resolved before a
# lease is ever consumed.
sub provider-for(Str:D $agent-id) {
	MCP::Client::Policy.new(
		provider => MCP::Client::Leases.new(
			inner      => $registry,
			table      => $table,
			agent-id   => $agent-id,
			roots      => { fs => '/srv/work', lock => '/srv/work' },
			concurrent => { $engine.live-agents },      # > 1 turns strict mode on
		),
		rules => MCP::Client::Policy.default-rules,
		:&on-ask,
	);
}

# The model's side of it:
#   lock_acquire { "paths": ["src/app.raku"], "ttl": 600 }
#   fs_edit      { "path": "src/app.raku", ... }
#   lock_release { "paths": ["src/app.raku"] }
=end code

=head1 DESCRIPTION

Two agents editing one checkout will, eventually, edit one file. Not at the
same instant — the calls are serialized by the server — but across the window
that matters: read the file, think about it, write it back. The second agent's
read happened before the first agent's write, and its write throws that away.
Nothing in the permission layer notices, because both calls were things their
agent was perfectly entitled to do.

C<MCP::Client::Leases> is the smallest thing that closes that window: an
in-process, advisory, bounded-wait lock table with two tools in front of it.
An agent about to work on part of the tree says so; another agent trying to
change the same part is told who has it and for how long. It is a provider
composer, satisfying the same duck type C<MCP::Client::Registry> and
C<MCP::Client::Policy> do — C<tools-for-llm> plus C<execute-tool-calls> — so it
stacks in wherever a provider goes.

=head2 What a lease is, and is not

A lease is B<advisory>. It is not a filesystem lock, it does not survive the
process, and nothing outside this table honours it. It is a claim one agent
makes and the other agents' tool layers respect, which is enough precisely
because every agent in the pack goes through this layer.

The single-call race is already handled elsewhere and needs no lease:
C<fs_edit>'s exact-match C<old-string> is B<optimistic concurrency control> —
the edit lands only if the text it expected is still there, so a call that lost
the race fails loudly instead of clobbering. What a lease protects is the
B<multi-step> window C<fs_edit> cannot see: read, decide, write; or the four
edits that only make sense applied together; or the rename that has to follow
the change to the file it renames.

B<Reads are unrestricted in v1.> There are no read-locks, and a lease does not
stop anybody reading what it covers — which means a non-locking reader can
still read a file halfway through somebody else's multi-step change and act on
what it saw. If that matters for a particular flow, have the reader take the
lease too: C<lock_acquire> then read then C<lock_release> gives a reader the
same window a writer gets, at the cost of contending for it.

=head2 Acquisition waits, but never for ever

C<lock_acquire> tries at once, and if the path is taken it B<waits> — up to
C<wait> seconds, polling the table about once a second — before it gives up and
returns the refusal. C<wait> defaults to 90 seconds and is capped at the
table's C<default-ttl> (300 out of the box).

This is a change of mind, and the economics are the whole of the argument. The
original design refused immediately, on the grounds that a bounded thing that
never waits cannot deadlock. It cannot — but it does not stop anybody waiting
either; it moves the waiting into the B<model>, which is the most expensive
place in the system to put it. A refused agent re-reads its instructions,
thinks about what to do instead, and calls C<lock_acquire> again — and every one
of those laps re-sends the entire conversation to a language model. Two agents
sharing one file can burn hundreds of thousands of prompt tokens taking turns
at a lock that was free after four seconds. Polling a hash inside the process
costs nothing at all.

What keeps it safe is that the wait is B<bounded twice over>. A wait is at most
C<wait> seconds, and every lease expires on its own at its TTL. More
importantly, an agent that already holds any lease is never allowed to park on
another: contention fails immediately and teaches it to release, deduplicate,
and atomically acquire its complete working set. The Table also registers each
real waiter and rejects a cycle of any length as defence in depth. Registration,
blocker discovery, cycle detection and grant are one locked transition; no
thread sleeps while the Table lock is held.

C<wait: 0> is the original behaviour exactly: attempt once, return the refusal,
never sleep. Nothing else about the refusal changed — same wording, same
holder-and-held-for shape — because a model that has learned to read it should
not have to learn again just because it arrived a minute later.

B<There is no queue and no fairness.> A lease that comes free is taken by
whoever's poll lands first, which may not be whoever has waited longest, and a
third agent that never waited at all can win it by asking at the right
microsecond. A fair queue is a much bigger object — it has to survive holders
that die, waiters that are cancelled, and a released lock nobody is left to take
— and none of it is needed for "two agents want one file". The refusal at the
deadline says who is holding it, which is enough to work with.

The refusal is still the interesting message, and it is still written to be
acted on: it names the holder and how long they have held it, so the model can
work on something else and come back, or say who has the file. The tool
description teaches that, and teaches that the call may take a while.

=head2 Stale-write fence and provider pins

With C<MCP::Server::Tool::FileSystem>, successful C<read>, C<stat> and C<list>
results carry a hidden C<sha256-v1> revision. The layer caches it and adds the
reserved C<_expected-revisions> argument to the next C<fs_write>, C<fs_edit>,
C<fs_mkdir>, C<fs_move> or C<fs_delete>. The filesystem provider compares and
mutates under one lock. A changed target is refused before any side effect;
success advances the cache and failure invalidates it. A target never observed
by this agent is expected to be absent, so a blind overwrite fails closed.

Before forwarding a mutation, the exact covering lease generation is pinned.
Expiry and explicit release become pending until the provider returns, so the
same path cannot be granted to another agent while the original write is still
landing. C<Table.status> reports leases, waiters and pins together.

=head3 Waiting is a suspension, and hosts want to know

A batch's B<lock calls settle first> (see L</Never throws>), so an acquire that
waits delays the rest of its own batch. That is correct and not a regression:
the calls behind it are the edit the lease was taken to protect, and running
them first is precisely the race the lease exists to close.

It does mean an agent can be parked inside a tool call for a minute or more,
which a host with a fleet of them very much wants to know about — an agent
waiting on a lock is not working, and if the host caps concurrency by counting
working agents, a waiter should not be counted. Hence two optional callbacks:

=item C<on-wait-begin> — called once, when a wait really begins. An immediate
      grant never fires it, and neither does C<wait: 0>.
=item C<on-wait-end> — called once, on B<every> exit from the wait: the grant,
      the deadline, a cancel, or an exception on the way out.

Neither takes an argument: a composer belongs to one agent and carries its
C<agent-id>, so the host already knows who it is about. Both are B<shielded> —
a hook that throws is swallowed, because a broken bit of host bookkeeping must
not turn an acquire that was granted into an error the model has to interpret.

=head3 Cancelling a wait

The optional C<cancelled> thunk is asked, once per poll, whether anybody is
still waiting for this call's answer. When it answers true the wait stops at
that tick and the standard refusal comes back with a sentence noting that the
wait was cut short.

The question is deliberately B<that> one rather than "has somebody pressed
cancel", because the two come apart at the moment that matters. A host whose
run was cancelled typically settles it and stops waiting for the tool call
B<while the call is still in flight> — the call is detached, its answer has
nowhere to go — so a thunk that only reports "cancelled" goes false again
the instant the run finishes, and the wait it should have ended carries on
for its full deadline holding a thread (and possibly taking a lease nobody
will release). "Is there still a live, uncancelled run behind this call?" is
the shape that closes both cases.

It fails B<open>: a thunk that throws is read as "not cancelled" and the wait
runs its course. That is the opposite of the C<concurrent> thunk two sections
down, deliberately: over-waiting costs seconds of wall clock, while a falsely
cancelled acquire hands back a refusal for a lock that was there for the taking
— and the agent then edits a file it does not hold, or gives up on work it could
have done. When the two failure modes are "slow" and "wrong", the broken signal
should choose slow.

=head2 Strict when concurrent

By default this layer only enforces B<other> agents' leases: a call that would
change a path somebody else has claimed comes back as an C<is_error> naming
them, and everything else goes through untouched. A solo agent therefore never
sees the lease layer at all, which is the point — locking discipline is pure
overhead when there is nobody to contend with.

When the C<concurrent> thunk says more than one agent is live, the layer
switches to B<strict>: a mutating call must be covered by a lease this agent
holds, or it is refused with an error that teaches the fix ("another agent is
live; C<lock_acquire> first"). Strictness relaxes on its own when the last
sibling drains.

The thunk fails B<closed>. If it throws, or answers with something that cannot
be read as a count, the layer assumes concurrency and goes strict. This is the
opposite of the usual "broken signal → feature inactive" reflex, and
deliberately so: the failure mode of over-strictness is an agent that asks for
locks it did not need, and the failure mode of under-strictness is two agents
silently overwriting each other's work. One of those is visible in the
transcript and the other is not.

=head2 Where in the stack

Stack it B<under> the policy — C<Policy(Leases(Registry))>:

=item permission resolves B<before> a lease is consumed, so a call the human
      refuses never takes or checks a lock, and the lease layer's error is
      never the reason a permission prompt did not appear;
=item it is also under any escalation or retry layer, so a re-run of a refused
      call cannot walk around the lease by being asked a second time;
=item and it means the lease layer never has to know a policy exists. It has
      no ask surface, calls nothing that could open one, and holds no lock
      while calling anybody else's code.

That placement is also why this class does B<not> delegate C<interactive>,
C<grants>, C<elicit-hook> or anything else policy-shaped to its inner provider,
and why it needs no C<.can('grants')> subclass the way
C<LLM::Agent::Subagents> grew one. A composer that sits B<over> a policy has to
keep the policy's own surface reachable through it, or a host that introspects
the provider loses the human seam; a composer that sits B<under> one has the
policy on the outside already, where the host is looking. If you invert the
stack you take that on yourself.

Rule names, C<roots> keys and C<path-params> patterns are read at B<this>
layer's position, exactly as a policy's are: under a registry a call arrives
with the prefix already stripped, over one it has not been. Getting it wrong is
quiet — no path is ever located, so nothing is ever enforced.

=head2 The published tools

Two, published without any registry prefix, the way
C<LLM::Agent::Subagents> publishes C<task>:

=item C<lock_acquire(paths, ttl?, wait?)> — claim paths, all or nothing,
      waiting out a contended one for up to C<wait> seconds;
=item C<lock_release(paths?)> — give them back; bare, everything you hold.

An inner provider that publishes either name has its declaration B<dropped>
from the catalogue rather than published twice — this composer routes on those
names, so publishing somebody else's version of them would be a lie. That
holds even with C<< publish-tools => False >>, the solo-only configuration
where the two tools are hidden from the model entirely.

=head2 Never throws

C<execute-tool-calls> keeps the provider contract exactly: a refusal, a
malformed call, a lock that could not be taken, an inner provider that died —
each is one C<is_error> result in the caller's own order, and the calls around
it are unaffected. C<tools-for-llm> keeps the deliberate asymmetry: an inner
provider that cannot list its tools throws, because publishing a silently
shorter catalogue leaves a model wondering where a capability went.

Within a mixed batch the B<lock calls settle first>, in order, before any other
call is judged. So C<lock_acquire> and the edit it protects may travel in one
batch, which is how a model that has just been told to lock first will write
it.

Results from the inner provider are passed through as they came, with one
exception: when the layer could not judge a path and is not being strict, the
result gets a C<leases-warning> key saying so (only if it was an object — a
result of some other shape is never reshaped to carry a warning).

=head1 EXAMPLES

The solo case, where the layer costs nothing. No C<concurrent> thunk means
never strict, so an unlocked write goes straight through and only another
holder's lease can stop anything:

=begin code :lang<raku>
my $leases = MCP::Client::Leases.new(
	inner => $registry, table => $table, agent-id => 'main',
	roots => { fs => '/srv/work', lock => '/srv/work' },
);
=end code

Note the C<lock> entry in C<roots>. Roots are matched by tool-name B<prefix>,
and the published tools are called C<lock_acquire>/C<lock_release>, so a table
that only knows about C<fs> leaves the lock tools with no root to measure a
relative path from — and C<'src/app.raku'> locked as a relative path will not
be recognised as the same location as C</srv/work/src/app.raku> written by
C<fs_write>. Either add a C<lock> entry pointing at the same directory the
C<fs> tools use, or give the table a C<''> catch-all.

Enforcement follows the tools that change things, which is configurable
because not every server calls them what the C<MCP::Server::Tool::FileSystem>
pack does. Patterns are the same trailing-C<*> globs a rule's C<tool> is:

=begin code :lang<raku>
my $leases = MCP::Client::Leases.new(
	inner => $inner, table => $table, agent-id => 'writer-1',
	enforced-tools => <fs_write fs_edit fs_mkdir fs_move fs_delete patch_*>,
	path-params    => { patch_apply => ['target',] },
);
=end code

A fleet that counts working agents wants the suspension hooks, and a fleet with
a cancel button wants the thunk. All three are plain closures over what the host
already has:

=begin code :lang<raku>
my $leases = MCP::Client::Leases.new(
	inner => $registry, table => $table, agent-id => $agent-id,
	roots => %( fs => $root, lock => $root ),
	concurrent => &live-agents,
	# An agent parked on a lock is not working: give its queue slot back
	# for the duration, exactly as one parked on a question does.
	on-wait-begin => { $subagents.suspend-agent($agent-id) },
	on-wait-end   => { $subagents.resume-agent($agent-id) },
	# And stop waiting the moment this agent's run is cancelled.
	cancelled     => { $run.defined && $run.is-cancelled },
);
=end code

Releasing when an agent stops is not this layer's job — it has no idea when
that happened. The engine that owns the agents does it, off the run's
C<drained> (never its C<result>: a detached write may still be landing when the
answer is already in):

=begin code :lang<raku>
$run.drained.then({ $table.release-holder($agent-id) });
$engine.on-shutdown({ $table.release-all });
=end code

=head1 SEE ALSO

L<MCP::Client::Policy|lib/MCP/Client/Policy.rakumod> — the permission layer
this one stacks under, and the source of the C<roots>/C<path-params>
conventions it locates paths with.

L<MCP::Client::Leases::Table|lib/MCP/Client/Leases/Table.rakumod> — the lease
book itself, and the plain-data API a status surface reads.

=end pod

use JSON::Fast;

use MCP::Client::Exceptions;
use MCP::Client::Leases::Table;
use MCP::Client::Policy::Rules;

unit class MCP::Client::Leases;

#| The tools this composer publishes and routes on, without any registry
#| prefix — a lease is about the workspace, not about one server.
our constant LOCK-TOOLS = <lock_acquire lock_release>;

my constant ACQUIRE = 'lock_acquire';
my constant RELEASE = 'lock_release';

# The MCP::Server::Tool::FileSystem pack's mutating tools, under the prefix it
# publishes them with. Everything else is somebody else's naming, so it is an
# option rather than an assumption.
my constant DEFAULT-ENFORCED = <fs_write fs_edit fs_mkdir fs_move fs_delete>;
my constant REVISION-SCHEME = 'sha256-v1';
my constant EXPECTED-REVISIONS = '_expected-revisions';
my constant CAS-TOOLS = <fs_write fs_edit fs_mkdir fs_move fs_delete>.Set;

#|( How long a contended C<lock_acquire> waits when the call does not say.
    B<Ninety seconds.>

    It is a guess about people, not about machines: it is long enough to
    ride out an ordinary multi-step edit (read, think, write, release) by
    the agent in front, and short enough that a model told "this may take
    a while" is not left holding a tool call for an unexplainable length of
    time. What makes the number safe rather than merely plausible is the
    cap below — the wait cannot outlast the lease it is waiting on. )
our constant DEFAULT-WAIT-SECONDS = 90;

#|( How often a waiting acquire retries: about a second.

    Slow enough that a hundred waiters cost nothing measurable, fast
    enough that the time between "the holder released it" and "the waiter
    has it" is noise next to one model round trip — which is the whole
    point of waiting here rather than in the model. It also bounds how
    long a cancel takes to be noticed, which is the other thing this
    number decides. )
my constant WAIT-POLL-SECONDS = 1;

# Everything .new accepts. Named rather than inferred so that a typo -- `root`
# for `roots`, `enforced` for `enforced-tools` -- is an error at construction
# instead of a lease layer that silently enforces nothing.
my constant OPTIONS =
	<inner table agent-id roots path-params enforced-tools concurrent publish-tools default-ttl
	 on-wait-begin on-wait-end cancelled>.Set;

has $.inner is required;

#| The lease book, shared by every composer over the same workspace.
has MCP::Client::Leases::Table:D $.table is required;

#| Who this composer's calls are made by. One id per agent: it is the identity
#| a lease is held under, the identity a refusal names, and what
#| C<Table.release-holder> is given when the agent stops.
has Str:D $.agent-id is required;

#| Whether C<lock_acquire>/C<lock_release> appear in the catalogue. C<False> is
#| the solo-only configuration: other agents' leases are still enforced (there
#| may be none), but this agent is not invited to take any.
has Bool:D $.publish-tools = True;

#| How long this agent's leases last when C<lock_acquire> does not say.
#| Undefined — the default — means the table's own C<default-ttl>, which is
#| where a workspace-wide answer belongs; set it to give one agent a shorter or
#| longer leash than its siblings.
has Real $.default-ttl;

#| Answers how many agents are live. More than one turns strict mode on. A
#| thunk rather than a value because liveness changes underneath a long batch,
#| and B<fails closed>: one that throws, or answers with something unreadable,
#| is taken to mean "concurrent". Called once per batch, on the calling thread,
#| so it must be a leaf — never re-enter the provider stack from it.
has &.concurrent;

#|( Called once when a contended C<lock_acquire> starts waiting, and never
    for an acquire that was granted at once or asked not to wait. Takes no
    arguments — this composer is one agent's, and carries its C<agent-id>.

    B<Shielded>: a hook that throws is swallowed. Host bookkeeping that
    breaks must not turn a granted lock into an error the model has to
    make sense of. )
has &.on-wait-begin;

#|( The other half, called once on B<every> exit from a wait that began —
    the grant, the deadline, a cancel, and an exception on the way out
    (it is a C<LEAVE>). Shielded, exactly as C<on-wait-begin> is. )
has &.on-wait-end;

#|( Asked once per poll whether this call's answer is still wanted — a
    cancelled run, or one that has already settled without it. A true
    answer ends the wait at that tick with the standard refusal. Absent
    means a wait always runs its course. See the Pod for why the question
    is that one rather than "was it cancelled".

    B<Fails open>, unlike C<concurrent>: a thunk that throws is read as
    "not cancelled". Over-waiting costs seconds; a falsely cancelled
    acquire hands back a refusal for a lock that was free, and the agent
    then works without the lease it should have had. )
has &.cancelled;

has %!roots;
has %!path-params;
has @!enforced;
has Lock $!observation-lock .= new;
has %!observations;
has Int $!next-waiter = 0;

submethod TWEAK(
	:$inner, :$table, :$agent-id, :$roots, :$path-params, :$enforced-tools,
	:&concurrent, :$publish-tools, :$default-ttl,
	:&on-wait-begin, :&on-wait-end, :&cancelled,
	*%unknown
) {
	my @unknown = %unknown.keys.grep({ !OPTIONS{$_} }).sort;
	die X::MCP::Client.new(
		detail => "unknown option(s) for a lease layer: '{@unknown.join(q{', '})}'; a lease layer "
			~ 'is made of ' ~ OPTIONS.keys.sort.join(', '),
	) if @unknown;

	# .can rather than .^can, and structural rather than nominal: the same
	# contract MCP::Client::Policy and MCP::Client::Registry check, for the same
	# reason -- a client, a server, a registry and a policy share no ancestor.
	die X::MCP::Client.new(
		detail => 'cannot build a lease layer over '
			~ ($!inner.defined ?? 'a ' ~ $!inner.^name !! 'the ' ~ $!inner.^name ~ ' type object')
			~ ': a tool provider must be a defined object with both a tools-for-llm and an '
			~ 'execute-tool-calls method',
	) unless $!inner.defined && provider-shaped($!inner);

	die X::MCP::Client.new(
		detail => 'a lease layer needs a non-empty agent-id: it is the identity leases are held '
			~ 'under, and the one a refusal names',
	) unless $!agent-id.chars;

	die X::MCP::Client.new(
		detail => 'the default-ttl of a lease layer must be a positive number of seconds',
	) if $!default-ttl.defined && (!($!default-ttl > 0) || $!default-ttl ~~ Bool);

	%!roots = validate-roots($roots);
	%!path-params = validate-path-params($path-params);

	# Validated as a rule's tool pattern is, so every table in the stack agrees
	# about what a pattern is -- and so 'fs*write' fails here rather than
	# matching nothing for the rest of the run.
	my $wanted = $enforced-tools // DEFAULT-ENFORCED;
	die X::MCP::Client.new(
		detail => 'the enforced-tools of a lease layer must be a list of tool patterns, not a '
			~ $wanted.^name,
	) unless $wanted ~~ Positional;

	@!enforced = $wanted.list.map(-> $pattern {
		validate-rule({ tool => $pattern, decision => 'ask' }, what => 'enforced tool pattern')<tool>;
	});
}

#| The tool-name-prefix to directory table, as a copy.
method roots(--> Hash:D) {
	%!roots.Hash;
}

#| The per-tool overrides of the C<path>/C<from>/C<to> convention, as a copy.
method path-params(--> Hash:D) {
	%!path-params.map({ $_.key => $_.value.List }).Hash;
}

#| The tool patterns whose calls must clear the lease table, as a copy.
method enforced-tools(--> List:D) {
	@!enforced.List;
}

# === The bridge ===

#|( The inner provider's declarations plus C<lock_acquire> and
    C<lock_release>.

    An inner provider that publishes either name has it B<dropped> rather
    than published twice: this composer routes on those names, so a second
    declaration of one would describe a tool the model cannot actually
    reach. The drop happens whether or not this composer publishes its own
    (C<< publish-tools => False >> hides them from the catalogue but does
    not stop them working, so the name is still spoken for).

    Throws whatever the inner provider throws while listing. )
method tools-for-llm(--> List) {
	my @published = $!inner.tools-for-llm.list.grep({
		!LOCK-TOOLS.first(* eq (tool-name-of($_) // ''));
	});

	return @published.List unless $!publish-tools;
	(|@published, acquire-declaration(), release-declaration()).List;
}

#|( Every call, answered: the lock calls here, the mutating ones checked
    against the lease table, everything else forwarded to the inner
    provider as one batch — and one result per call in the caller's order.

    B<Never throws.> A malformed call, a contended path, an unreadable
    argument and an inner provider that died all come back as C<is_error>
    results.

    The lock calls settle B<first>, in order, before any other call in the
    batch is judged: a C<lock_acquire> and the edit it protects may travel
    together, which is how a model that has just been told to lock first
    will write it. )
method execute-tool-calls(@tool-calls --> List) {
	# Read once, here: liveness changes underneath a long batch, and a batch
	# half-judged strict and half not would be impossible to explain.
	my Bool $strict = self!strict-now;

	my @results;
	my @locks;
	my @rest;

	for @tool-calls.kv -> $index, $call {
		my $function = $call ~~ Associative ?? $call<function> !! Any;
		# Stringified rather than passed through: a call whose id is a number
		# must not turn into a type error on the way into a refusal message.
		my $id = $call ~~ Associative ?? ($call<id> // '').Str !! '';
		my $name = tool-name-of($call);

		if $name.defined && LOCK-TOOLS.first(* eq $name) {
			@locks.push: %( :$index, :$id, :$name, call => $call );
		}
		else {
			@rest.push: %( :$index, :$id, :$name, call => $call, arguments => $function );
		}
	}

	# 1. The locks, each shielded on its own: "never throws" is the contract,
	#    and a future edit that forgets it must not take the batch down.
	for @locks -> %item {
		my $answer;
		my $threw;
		{
			CATCH { default { $threw = $_ } }
			$answer = self!run-lock(%item<name>, %item<call>, %item<id>);
		}

		@results[%item<index>] = $threw.defined
			?? error-result(
				%item<id>,
				'The lease layer failed: ' ~ ($threw.message.lines.head // $threw.^name),
			)
			!! $answer;
	}

	# 2. Everything else, judged against the table as it now stands.
	my @forward;
	for @rest -> %item {
		my $name = %item<name>;

		# A call whose name cannot be read is not one this layer can claim, so
		# it goes to the inner provider -- which answers it with its own
		# well-formed error rather than a second opinion invented here.
		unless $name.defined && self!enforced($name) {
			@forward.push: %( |%item, warning => Str );
			next;
		}

		my $function = %item<arguments>;
		my %check = self!check-lease(
			$name,
			$function ~~ Associative ?? $function<arguments> !! Str,
			$strict,
		);

		if %check<refuse>.defined {
			@results[%item<index>] = error-result(%item<id>, %check<refuse>);
		}
		else {
			@forward.push: %(
				|%item, warning => %check<warning>,
				pin-paths => (%check<pin-paths> // []).List,
			);
		}
	}

	# 3. One batch to the inner provider, exactly as Policy and Subagents do it.
	if @forward.elems {
		my @ready;
		my @pins;
		for @forward -> %item {
			my @paths = %item<pin-paths> ~~ Positional
				?? %item<pin-paths>.list !! ();
			if @paths {
				my %pin = $!table.pin(holder => $!agent-id, paths => @paths);
				unless %pin<pinned> {
					@results[%item<index>] = error-result(
						%item<id>,
						"{%item<name>}: the covering lease expired or was released before "
							~ 'the provider call began. Reacquire it and try again.',
					);
					next;
				}
				@pins.push: %pin<token>;
			}
			my $call = self!with-expectations(%item);
			@ready.push: %( |%item, :$call );
		}
		LEAVE $!table.unpin($_) for @pins;

		my @calls = @ready.map({ $_<call> }).List;
		my @answers;
		my $failure;
		if @ready {
			CATCH { default { $failure = $_ } }
			# `.eager`, and it is not decoration: a provider that hands back a
			# LAZY list has not done the work yet, and reifying it where the
			# results are indexed -- below, outside this CATCH -- would turn a
			# provider that throws into an exception this method promises never
			# to raise.
			@answers = $!inner.execute-tool-calls(@calls).list.eager;
		}

		for @ready.kv -> $at, %item {
			self!learn-result(%item, @answers[$at], $failure);
			@results[%item<index>] = $failure.defined
				?? error-result(
					%item<id>,
					'The tool provider failed: ' ~ ($failure.message.lines.head // $failure.^name),
				)
				!! annotated(@answers[$at], %item<id>, %item<warning>);
		}
	}

	@results.List;
}

# === Enforcement ===

# Whether one call must clear the lease table before it is forwarded.
method !enforced(Str:D $name --> Bool:D) {
	so @!enforced.first({ match-tool($_, $name) }).defined;
}

# Whether siblings are live, and therefore whether an unleased mutation is
# refused. Fails closed in every direction a signal can be broken in -- see the
# Pod for why this deliberately differs from the usual fail-inactive reflex.
method !strict-now(--> Bool:D) {
	return False without &!concurrent;

	my $answer;
	my $threw;
	{
		CATCH { default { $threw = $_ } }
		$answer = &!concurrent();
	}

	return True if $threw.defined;
	return True without $answer;
	return $answer.so if $answer ~~ Bool;
	return $answer > 1 if $answer ~~ Real;
	True;
}

# One mutating call against the table. Answers an empty hash to let it through,
# `refuse` with the message to stop it, or `warning` to let it through with a
# note attached to whatever the provider says.
method !check-lease(Str:D $name, $raw-arguments, Bool:D $strict --> Hash:D) {
	# A tool configured to name no locations is a tool this layer has nothing
	# to say about -- not one whose locations could not be read.
	my @params = path-params-for($name, %!path-params);
	return %() unless @params;

	my $arguments = parse-arguments($raw-arguments);
	my $root = root-for($name, %!roots);
	my @located = located-args($name, $arguments, %!path-params, $root);

	unless @located {
		my $why = $arguments.defined
			?? "'$name' was called without any of the location arguments the lease layer knows "
				~ "about ({@params.join(', ')})"
			!! "the arguments to '$name' are not a JSON object, so the lease layer cannot tell "
				~ 'which paths it would change';
		return unjudged($name, $why, $strict);
	}

	my @other;
	my @unreadable;
	my @unknown;
	my @free;
	my @own;

	for @located -> %arg {
		# Present, but not something a location can be read out of: an object
		# where a path was declared, or a null.
		unless %arg<path> ~~ Str:D {
			@unreadable.push: %arg<param>;
			next;
		}

		# A string, but not one the lexical model can reason about -- a '..'
		# segment, a backslash, a null byte, an empty string. The table would
		# answer 'free' for it whenever no other lease happens to be nearby,
		# which is true and useless: nothing was compared. Asked here so the
		# answer says so, and so the fail-closed rules below apply to it.
		unless judgeable(%arg<path>) {
			@unknown.push: %arg<path>;
			next;
		}

		my %verdict = $!table.covering(holder => $!agent-id, path => %arg<path>);

		given %verdict<verdict> {
			when 'other'   { @other.push: %( path => %arg<path>, |%verdict ) }
			when 'own'     { @own.push: %arg<path> }
			when 'unknown' { @unknown.push: %arg<path> }
			when 'free'    { @free.push: %arg<path> }
		}
	}

	# Somebody else's lease stops the call whether or not anything is strict:
	# that is the one rule this layer always enforces.
	if @other {
		return %( refuse => "$name: " ~ @other.map({ conflict-text($_) }).join(' ')
			~ ' The call was not made. Wait and try again, work somewhere else, or say who is '
			~ 'holding it.' );
	}

	if @unreadable || @unknown {
		my @named = |@unreadable.map({ "the '$_' argument" }), |@unknown.map({ "'$_'" });
		return unjudged(
			$name,
			"the lease layer cannot tell where {@named.join(', ')} points",
			$strict,
		);
	}

	# Strict mode wants every path covered, not merely one of them: a move whose
	# destination nobody has locked is still a write nobody has locked.
	if $strict && @free {
		return %( refuse => "$name: another agent is live, and this agent holds no lock on "
			~ @free.map({ "'$_'" }).join(', ') ~ ". Call {ACQUIRE} with those paths first, then "
			~ 'try this call again.' );
	}

	%( pin-paths => @own.List );
}

# Copy only calls to the standard filesystem mutators. The reserved argument is
# deliberately not part of their advertised schemas and never mutates the
# model-authored call object. An unobserved target is expected to be absent,
# making a blind overwrite fail at the provider boundary.
method !with-expectations(%item) {
	my $name = %item<name> // '';
	return %item<call> unless CAS-TOOLS{$name};
	my $call = %item<call>;
	return $call unless $call ~~ Associative;
	my %copy = $call.Hash;
	my $function = %copy<function>;
	return $call unless $function ~~ Associative;
	my %function = $function.Hash;
	my $arguments = parse-arguments(%function<arguments>);
	return $call without $arguments;

	my $root = root-for($name, %!roots);
	my @located = located-args($name, $arguments, %!path-params, $root);
	my %expected;
	for @located -> %location {
		next unless %location<path> ~~ Str:D;
		my $token = $!observation-lock.protect: {
			%!observations{%location<path>} // REVISION-SCHEME ~ ':absent'
		};
		%expected{%location<param>} = $token;
	}
	return $call unless %expected;

	my %arguments = $arguments.Hash;
	%arguments{EXPECTED-REVISIONS} = %expected;
	%function<arguments> = %arguments;
	%copy<function> = %function;
	%copy;
}

# Consume a filesystem pack's machine result. The bridge deliberately names it
# `structured_content`; wire MCP calls used `structuredContent` before the
# bridge. Failed conditional mutations invalidate our prior observation so a
# retry must re-read rather than adopting a token from an error response.
method !learn-result(%item, $answer, $failure --> Nil) {
	my $name = %item<name> // '';
	my $function = %item<arguments>;
	my $arguments = parse-arguments(
		$function ~~ Associative ?? $function<arguments> !! Str,
	);
	return without $arguments;
	my $root = root-for($name, %!roots);
	my @located = located-args($name, $arguments, %!path-params, $root);
	@located.push: %( param => 'path', path => $root )
		if $name eq 'fs_list' && !@located && $root ~~ Str:D;

	if $failure.defined || $answer !~~ Associative || $answer<is_error> {
		if CAS-TOOLS{$name} {
			self!forget(@located);
		}
		return;
	}
	my $structured = $answer<structured_content>;
	unless $structured ~~ Associative
		&& ($structured<revisionScheme> // '') eq REVISION-SCHEME
		&& $structured<revisions> ~~ Associative {
		self!forget(@located) if CAS-TOOLS{$name};
		return;
	}

	my %revisions = $structured<revisions>.Hash;
	$!observation-lock.protect: {
		for @located -> %location {
			next unless %location<path> ~~ Str:D;
			my $revision = %revisions{%location<param>};
			next unless $revision ~~ Associative && $revision<token> ~~ Str:D;
			%!observations{%location<path>} = $revision<token>;
		}
	};
}

method !forget(@located --> Nil) {
	$!observation-lock.protect: {
		for @located.grep({ $_<path> ~~ Str:D }) -> %location {
			%!observations{%location<path>}:delete;
		}
	};
}

# Whether the lexical containment model can say anything at all about a path.
# Every usable path is inside itself; nothing else is.
my sub judgeable(Str:D $path --> Bool:D) {
	path-under($path, $path) eq 'yes';
}

# A path the layer could not judge: refused while siblings are live, allowed
# with a note when there is nobody to collide with.
my sub unjudged(Str:D $name, Str:D $why, Bool:D $strict --> Hash:D) {
	return %( refuse => "$name: $why, so the call was refused while other agents are live. "
		~ "Name each path as a plain path with no '..' segments and no backslashes, lock it with "
		~ "{ACQUIRE}, and try again." )
		if $strict;

	%( warning => "The lease layer did not check this call against the locks other agents hold: "
		~ "$why." );
}

my sub conflict-text(%clash --> Str:D) {
	my $where = %clash<leased> ne %clash<path> ?? " (locked as '{%clash<leased>}')" !! '';
	"'{%clash<path>}' is locked by {%clash<holder>}$where, held for {%clash<held-for>.Int}s.";
}

# === The lock tools ===

# One lock_acquire or lock_release, from its raw arguments to a result. Answers
# with a result Hash on every path; the caller shields it anyway.
method !run-lock(Str:D $name, $call, Str:D $id --> Hash:D) {
	my $function = $call ~~ Associative ?? $call<function> !! Any;
	my $arguments = parse-arguments($function ~~ Associative ?? $function<arguments> !! Str);

	return error-result($id, "$name: the arguments are not a JSON object. " ~ usage($name))
		without $arguments;

	my %paths = requested-paths($arguments<paths>);
	return error-result($id, "$name: {%paths<why>} " ~ usage($name)) unless %paths<ok>;

	my $root = root-for($name, %!roots);
	my @paths = %paths<paths>.map({ absolutize($_, $root) }).List;

	$name eq ACQUIRE
		?? self!do-acquire(@paths, $arguments<ttl>, $arguments<wait>, $id)
		!! self!do-release(@paths, $id);
}

method !do-acquire(@paths, $raw-ttl, $raw-wait, Str:D $id --> Hash:D) {
	return error-result(
		$id,
		"{ACQUIRE}: no paths were given, so nothing was locked. " ~ usage(ACQUIRE),
	) unless @paths.elems;

	my $ttl = $raw-ttl.defined ?? seconds-of($raw-ttl) !! $!default-ttl;
	return error-result(
		$id,
		"{ACQUIRE}: ttl must be a positive number of seconds. " ~ usage(ACQUIRE),
	) if $raw-ttl.defined && !$ttl.defined;

	# Nothing here is a Failure or a NaN: an unreadable `wait` is undefined
	# and refused by name, exactly as an unreadable `ttl` is. Zero is a
	# legitimate value -- it is the never-wait acquire this layer shipped
	# with -- so it is `seconds-of`'s positive-only rule plus a nought.
	my $wait = self!wait-seconds($raw-wait);
	return error-result(
		$id,
		"{ACQUIRE}: wait must be a number of seconds, zero or more. " ~ usage(ACQUIRE),
	) unless $wait.defined;

	my %got = self!attempt(@paths, $ttl);

	# The wait, and the ONE case that gets one: somebody else is holding
	# some of these paths right now. A malformed path will not become
	# well-formed by being asked about again, and a grant is a grant.
	my Bool $cut-short = False;
	if !%got<granted> && $wait > 0 && (%got<reason> // '') eq 'conflict' {
		my $waiter-id = $!agent-id ~ '-wait-' ~ ++$!next-waiter;
		%got = self!wait-attempt($waiter-id, @paths, $ttl);
		if !%got<granted> && (%got<reason> // '') eq 'conflict' {
			%got = self!wait-for-lease($waiter-id, @paths, $ttl, $wait, %got);
			$cut-short = %got<cut-short>.so;
		}
	}

	if %got<granted> {
		my @leases = %got<leases>.list;
		my $life = @leases.head<ttl>;
		return ok-result(
			$id,
			"{ACQUIRE}: locked " ~ quoted(@leases.map({ $_<path> })) ~ " for {$life.Int}s. "
				~ 'No other agent can change them until you release them, and they expire on '
				~ "their own if you do not. Call {RELEASE} as soon as you are done.",
		);
	}

	given %got<reason> {
		when 'conflict' {
			error-result(
				$id,
				"{ACQUIRE}: nothing was locked. "
					~ %got<conflicts>.list.map({ conflict-text($_) }).join(' ')
					~ ' Work on something else and try again later, or say that the path is taken.'
					# Appended rather than folded in: the sentences before it are
					# the refusal a model has already been taught to read, and
					# they are true whether or not anybody waited.
					~ ($cut-short ?? ' The wait for it was cut short.' !! ''),
			);
		}
		when 'unevaluable-path' {
			error-result(
				$id,
				"{ACQUIRE}: nothing was locked. These are not paths the lease layer can lock: "
					~ quoted(%got<unevaluable>.list) ~ ". A path is a plain non-empty string with "
					~ "no '..' segment, no backslash and no null byte; write it relative to the "
					~ 'workspace root, or in full.',
			);
		}
		when 'hold-and-wait' {
			error-result(
				$id,
				"{ACQUIRE}: nothing was locked. This agent already holds a lease and "
					~ 'waiting for another would permit a deadlock. Release what you hold, '
					~ 'then acquire the complete deduplicated working set in one call.',
			);
		}
		when 'deadlock' {
			error-result(
				$id,
				"{ACQUIRE}: nothing was locked because the wait would form a deadlock "
					~ "cycle ({%got<cycle>.list.join(' -> ')}). Release the current set and "
					~ 'acquire the complete working set atomically.',
			);
		}
		default {
			error-result($id, "{ACQUIRE}: nothing was locked. " ~ usage(ACQUIRE));
		}
	}
}

# One go at the table, with or without a ttl of our own. Every attempt a
# waiting acquire makes goes through here, so a retry is exactly the call
# the first attempt was -- including the all-or-nothing rule, which is what
# makes a refused attempt leave nothing behind to deadlock on.
method !attempt(@paths, $ttl --> Hash:D) {
	$ttl.defined
		?? $!table.acquire(holder => $!agent-id, :@paths, :$ttl)
		!! $!table.acquire(holder => $!agent-id, :@paths);
}

method !wait-attempt(Str:D $waiter-id, @paths, $ttl --> Hash:D) {
	$ttl.defined
		?? $!table.wait-attempt(
			:$waiter-id, holder => $!agent-id, :@paths, :$ttl, allow-hold => False,
		)
		!! $!table.wait-attempt(
			:$waiter-id, holder => $!agent-id, :@paths, allow-hold => False,
		);
}

#|( Poll for a contended lease until it comes free, the deadline passes, or
    the run is cancelled. C<%first> is the refusal the immediate attempt
    already produced, and it is what comes back if nothing changes.

    The exits, all four of them:

    =item B<granted> — the answer of the attempt that won, returned as-is,
          so a grant here is byte-identical to a grant that never waited;
    =item B<deadline> — the LAST attempt's refusal, which names whoever is
          holding it B<now> rather than whoever was holding it a minute ago;
    =item B<cancelled> — the last refusal with C<cut-short> set, at the
          first poll after the thunk went true;
    =item B<no longer a conflict> — a refusal for some other reason (a
          table that has started answering differently) ends the wait too;
          waiting is for contention and nothing else.

    C<on-wait-end> fires on every one of them, and on an exception on the
    way out, because it is a C<LEAVE>. )
method !wait-for-lease(
	Str:D $waiter-id, @paths, $ttl, Real:D $wait, %first --> Hash:D
) {
	shielded(&!on-wait-begin);
	LEAVE {
		$!table.cancel-wait($waiter-id);
		shielded(&!on-wait-end);
	}

	my $deadline = now + $wait;
	my %last = %first;

	loop {
		# Before the first sleep as well as after every one: a run that was
		# already cancelled when the call arrived must not sit out a tick to
		# find out.
		if wait-cancelled(&!cancelled) {
			%last<cut-short> = True;
			return %last;
		}

		my $left = $deadline - now;
		last if $left <= 0;

		sleep($left < WAIT-POLL-SECONDS ?? $left !! WAIT-POLL-SECONDS);
		if wait-cancelled(&!cancelled) {
			%last<cut-short> = True;
			return %last;
		}

		%last = self!wait-attempt($waiter-id, @paths, $ttl);
		return %last if %last<granted>;
		last unless (%last<reason> // '') eq 'conflict';
	}

	%last;
}

#|( The C<wait> argument in seconds: the default when the call does not say,
    zero for the never-wait acquire, and undefined for anything that is not
    a number of seconds at all (which the caller refuses by name).

    Capped at the table's C<default-ttl>, and the cap is not arbitrary. A
    lease on the workspace default expires by itself within that window, so
    a longer wait can only be spent waiting on a holder that has already
    been reaped and re-taken by somebody else — or on a holder who asked for
    an unusually long TTL, whom the refusal will name anyway. It also puts a
    ceiling on how long one tool call can take, which is a number a host
    with a tool deadline of its own has to be able to reason about. )
method !wait-seconds($given --> Real) {
	my Real $cap = $!table.default-ttl;
	return ($cap < DEFAULT-WAIT-SECONDS ?? $cap !! DEFAULT-WAIT-SECONDS).Real
		without $given;

	# A Bool is an Int, and `"wait": true` is not one second of anything.
	my $value = do given $given {
		when Bool  { Real }
		when Real  { $_ }
		when Str:D { $_.trim ~~ /^ \d+ [ '.' \d+ ]? $/ ?? +$_.trim !! Real }
		default    { Real }
	};

	return Real unless $value.defined && $value >= 0;
	($value > $cap ?? $cap !! $value).Real;
}

method !do-release(@paths, Str:D $id --> Hash:D) {
	my %gave = $!table.release(holder => $!agent-id, :@paths);
	my @released = %gave<released>.list;
	my @missing = %gave<not-held>.list;

	return ok-result(
		$id,
		"{RELEASE}: you hold no locks" ~ (@missing ?? ' on ' ~ quoted(@missing) !! '') ~ '.',
	) unless @released;

	ok-result(
		$id,
		"{RELEASE}: released " ~ quoted(@released) ~ '.'
			~ (@missing
				?? ' You did not hold ' ~ quoted(@missing) ~ ', so nothing was released for those.'
				!! ''),
	);
}

# === Declarations ===

my sub acquire-declaration(--> Hash:D) {
	%(
		type     => 'function',
		function => %(
			name        => ACQUIRE,
			description => 'Claim exclusive use of one or more files or directories before a '
				~ 'multi-step change to them (read-then-write, a series of edits that only make '
				~ 'sense together, a rename plus the edits that follow it). Other agents working '
				~ 'in this workspace are refused any change to what you hold, and told that you '
				~ 'hold it. It locks everything you asked for or nothing at all. If another '
				~ 'agent is holding one of the paths, THIS CALL WAITS for it — up to "wait" '
				~ 'seconds, ' ~ DEFAULT-WAIT-SECONDS ~ ' by default — so the call may take a '
				~ 'while and that is normal; do not treat a slow answer as a failure. If the '
				~ 'wait runs out you are told who holds the path and for how long, and that is '
				~ 'not a failure to retry blindly either — work on something else and come back '
				~ 'to it, or report that the path is taken. Acquire your complete deduplicated '
				~ 'working set in one call. If you already hold anything, a contended request '
				~ 'fails immediately: release it and reacquire the union rather than holding '
				~ 'one path while waiting for another. Locking a directory locks '
				~ 'everything under it. Lock as little as you can, for as short a time as you '
				~ "can, and call {RELEASE} the moment you are done.",
			parameters  => %(
				type       => 'object',
				properties => %(
					paths => %(
						type        => 'array',
						items       => %( type => 'string' ),
						description => 'The files or directories to lock, each a plain path '
							~ "with no '..' segments.",
					),
					ttl => %(
						type        => 'number',
						description => 'How many seconds to hold the lock for. It expires on '
							~ 'its own after that, so ask for roughly as long as the work will '
							~ 'take; locking the same path again before it expires extends it.',
					),
					wait => %(
						type        => 'number',
						description => 'How many seconds to wait for a path somebody else is '
							~ 'holding before giving up and telling you who has it. Defaults '
							~ 'to ' ~ DEFAULT-WAIT-SECONDS ~ ' seconds, which is usually the '
							~ 'right answer: waiting here costs nothing, while giving up and '
							~ 'asking again costs a whole round trip. Use 0 to be told '
							~ 'immediately instead of waiting.',
					),
				),
				required   => ('paths',),
			),
		),
	);
}

my sub release-declaration(--> Hash:D) {
	%(
		type     => 'function',
		function => %(
			name        => RELEASE,
			description => 'Give back locks taken with ' ~ ACQUIRE ~ ', so other agents can work '
				~ 'on those paths again. Call it as soon as the change is finished rather than at '
				~ 'the end of the task. With no arguments it releases everything you hold, which '
				~ 'is the right call when you are done working. Releasing something you do not '
				~ 'hold is harmless and is reported back to you.',
			parameters  => %(
				type       => 'object',
				properties => %(
					paths => %(
						type        => 'array',
						items       => %( type => 'string' ),
						description => 'The paths to release, named as they were locked. Omit '
							~ 'this to release every lock you hold.',
					),
				),
				required   => (),
			),
		),
	);
}

my sub usage(Str:D $name --> Str:D) {
	$name eq ACQUIRE
		?? 'Call it with { "paths": ["src/app.raku"] }, optionally with a "ttl" in seconds.'
		!! 'Call it with { "paths": ["src/app.raku"] }, or with no arguments to release '
			~ 'everything you hold.';
}

# === Helpers ===

# One host callback, called for effect and never for an answer. A hook that
# throws is swallowed here rather than shielded at the call site, because
# there are two of them and one of them is a LEAVE: an exception out of a
# LEAVE would replace whatever the method was already returning.
my sub shielded(&hook --> Nil) {
	return without &hook;
	CATCH { default { } }
	&hook();
	Nil;
}

# Whether the run this acquire belongs to has been cancelled. FAILS OPEN --
# a thunk that throws is read as 'not cancelled', which is the deliberate
# opposite of `concurrent`'s fail-closed rule. See the Pod: over-waiting is
# slow, a falsely cancelled acquire is wrong.
my sub wait-cancelled(&cancelled --> Bool:D) {
	return False without &cancelled;

	my $answer;
	my $threw;
	{
		CATCH { default { $threw = $_ } }
		$answer = &cancelled();
	}

	return False if $threw.defined;
	$answer.defined && $answer.so;
}

# Whether an object implements the bridge pair: the whole of the provider
# contract, and the same test MCP::Client::Policy makes.
my sub provider-shaped($provider --> Bool:D) {
	so $provider.can('tools-for-llm') && $provider.can('execute-tool-calls');
}

my sub tool-name-of($call --> Str) {
	return Str unless $call ~~ Associative;
	my $function = $call<function>;
	return Str unless $function ~~ Associative;
	$function<name> ~~ Str:D ?? $function<name> !! Str;
}

# The arguments of a call, parsed exactly as MCP::Client's own bridge and
# MCP::Client::Policy parse them: a hash is a hash, an empty or whitespace-only
# string is a call with no arguments, and anything else is JSON. Anything that
# will not parse comes back undefined, which every caller here reads as "the
# locations of this call cannot be known".
my sub parse-arguments($raw) {
	my $args = $raw // %();
	return $args.Hash if $args ~~ Associative;
	return %() if $args.Str.trim eq '';

	my $parsed;
	{
		CATCH { default { $parsed = Nil } }
		$parsed = from-json($args.Str);
	}

	$parsed ~~ Associative ?? $parsed.Hash !! Any;
}

# The `paths` argument of a lock call. A bare string is taken as one path --
# models write that often enough that refusing it would teach nothing -- and
# anything that is not a list of strings is refused by name rather than
# silently dropped.
my sub requested-paths($given --> Hash:D) {
	return %( ok => True, paths => ().List ) without $given;
	return %( ok => True, paths => ($given.Str,).List ) if $given ~~ Str:D;

	return %( ok => False, why => "paths must be a list of strings, not a {$given.^name}." )
		unless $given ~~ Positional;

	my @bad = $given.list.grep({ !($_ ~~ Str:D) });
	return %( ok => False, why => 'every path must be a string.' ) if @bad;

	%( ok => True, paths => $given.list.map(*.Str).List );
}

# A ttl as a model may write it: a JSON number, or a string that is plainly one
# (they do, often enough that refusing it would teach nothing). Matched rather
# than coerced, so nothing here can produce a Failure or a NaN. Anything else,
# and anything not positive, comes back undefined and is refused by name.
my sub seconds-of($given --> Real) {
	my $value = do given $given {
		# A Bool is an Int, and `"ttl": true` is not thirty seconds of anything.
		when Bool  { Real }
		when Real  { $_ }
		when Str:D { $_.trim ~~ /^ \d+ [ '.' \d+ ]? $/ ?? +$_.trim !! Real }
		default    { Real }
	};

	$value.defined && $value > 0 ?? $value !! Real;
}

my sub quoted(@items --> Str:D) {
	@items.map({ "'$_'" }).join(', ');
}

my sub error-result($id, Str:D $content --> Hash:D) {
	%(
		role => 'tool',
		tool_call_id => $id,
		content => $content,
		is_error => True,
	);
}

my sub ok-result($id, Str:D $content --> Hash:D) {
	%(
		role => 'tool',
		tool_call_id => $id,
		content => $content,
		is_error => False,
	);
}

# An inner provider's answer, on its way back out. Passed through exactly as it
# came: this layer adds no shape of its own, because the layer above (a policy,
# a registry) already normalises and a second opinion would only differ. The two
# exceptions are a missing answer -- one result per call is the contract, and a
# provider that came up short must not leave a hole -- and the warning key,
# which is only ever merged into an answer that was an object to begin with.
my sub annotated($answer, $id, $warning) {
	return error-result($id, 'The tool provider returned no result for this call') without $answer;
	return $answer unless $warning.defined && $answer ~~ Associative;

	my %result = $answer.Hash;
	%result<leases-warning> = $warning;
	%result;
}
