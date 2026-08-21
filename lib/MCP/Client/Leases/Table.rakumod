=begin pod

=head1 NAME

MCP::Client::Leases::Table - the in-process lease book two agents share

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Leases::Table;

my $table = MCP::Client::Leases::Table.new(default-ttl => 300);

my %got = $table.acquire(holder => 'writer-1', paths => ['/srv/src', '/srv/README.md']);
say %got<granted>;                        # True

my %no = $table.acquire(holder => 'reviewer-1', paths => ['/srv/src/app.raku']);
say %no<granted>;                         # False
say %no<conflicts>[0]<holder>;            # writer-1
say %no<conflicts>[0]<held-for>.Int;      # 3

say $table.covering(holder => 'writer-1', path => '/srv/src/app.raku')<verdict>;    # own
say $table.covering(holder => 'reviewer-1', path => '/srv/src/app.raku')<verdict>;  # other

$table.release(holder => 'writer-1');     # bare: everything this holder has
=end code

=head1 DESCRIPTION

The state behind L<MCP::Client::Leases|lib/MCP/Client/Leases.rakumod>: which
agent has claimed which part of the workspace, and until when. It is a plain
object with a lock, owned by whatever owns the agents — one table per shared
workspace, shared by every composer that fronts an agent working in it.

Everything it answers is B<plain data>, and contention is a B<value> rather
than an exception: C<acquire> either grants, or comes back saying who is in the
way and for how long they have been there. That is the whole reason the lease
layer above it can promise never to throw from a tool call.

=head2 A lease, and what it covers

A lease is one path — a file or a directory — claimed exclusively by one holder
for a while:

=begin code :lang<raku>
{
	path        => '/srv/src',      # as the caller gave it, already absolutized
	holder      => 'writer-1',      # an agent id
	acquired-at => Instant,
	ttl         => 300,             # seconds
	expires-at  => Instant,
	held-for    => 12.4,            # seconds, as at the moment of the snapshot
	expires-in  => 287.6,
}
=end code

A lease on a directory covers everything under it, by the same B<lexical>,
segment-wise containment test the permission engine uses
(C<MCP::Client::Policy::Rules>'s C<path-under>). Nothing here touches a
filesystem: the paths belong to the B<server's> filesystem, which may not be
this machine's at all.

Containment is checked in B<both directions> when a lease is taken. Claiming
C</srv/src> collides with somebody else's lease on C</srv/src/app.raku> just as
surely as the other way round, and an C<unknown> in either direction (a C<..>
segment, a backslash, an absolute path measured against a relative one) counts
as a collision. Fail-closed: a path the table cannot reason about is a path it
will not hand out.

=head2 All or nothing

C<acquire> grants every path it was asked for, or none of them. Partial grants
are how two agents each holding half of what they need come to sit and wait for
each other; refusing the whole request means a caller is never left holding
something it cannot use. C<wait-attempt> adds an atomic waiter registry for a
composer that chooses bounded waiting: it records blocker edges, rejects cycles
of any length, and never sleeps under the Table lock. The standard composer
also refuses hold-and-wait entirely.

=head2 Expiry is lazy

Every operation reaps expired leases first, inside the lock, before it looks at
anything. There is no timer thread and nothing to shut down: a table nobody
calls is a table doing nothing, and a wedged holder's claim evaporates the
moment somebody else asks about it. C<default-ttl> is 300 seconds; a per-call
C<ttl> overrides it, and a holder re-acquiring a path it already holds refreshes
the clock rather than stacking a second lease.

=head2 Thread safety

One lock, held only across state transitions and never while calling anybody
else's code. Readers get deep copies. C<status> returns leases, waiter edges and
in-flight mutation pins from one instant. A pin keeps its exact lease generation
alive while provider code runs; expiry or release is applied after C<unpin>.

=head1 EXAMPLES

The contention answer is the interesting one, because it is what a model is
told. Everything a refusal needs to be actionable is in it — who, what, and how
long they have had it:

=begin code :lang<raku>
my %no = $table.acquire(holder => 'reviewer-1', paths => ['/srv/src/app.raku']);

unless %no<granted> {
	for %no<conflicts>.list -> %clash {
		say "{%clash<path>} is inside {%clash<leased>}, held by {%clash<holder>} "
			~ "for {%clash<held-for>.Int}s";
	}
}
=end code

A holder that wedges is handled by the TTL, and one that finishes is handled by
whoever is watching it. Both are one call:

=begin code :lang<raku>
# The agent's run finished (drained, not merely answered): tidy up after it.
$table.release-holder('writer-1');

# Engine shutdown.
$table.release-all;
=end code

Re-acquiring is how a long edit keeps its claim alive without a second kind of
call — the TTL restarts, and no second lease appears:

=begin code :lang<raku>
$table.acquire(holder => 'writer-1', paths => ['/srv/src'], ttl => 30);
# ... 25 seconds of work later ...
$table.acquire(holder => 'writer-1', paths => ['/srv/src'], ttl => 30);
say $table.leases.elems;   # 1
=end code

=head1 SEE ALSO

L<MCP::Client::Leases|lib/MCP/Client/Leases.rakumod> — the provider that
publishes C<lock_acquire>/C<lock_release> over this table and enforces it on
mutating calls.

=end pod

use MCP::Client::Exceptions;
use MCP::Client::Policy::Rules;

unit class MCP::Client::Leases::Table;

#| How long a lease lasts when the caller does not say. The backstop for a
#| holder that wedged: nothing else releases the leases of an agent that has
#| stopped running without saying so, and a workspace locked forever by a dead
#| agent is worse than one whose locks are only mostly durable.
has Real:D $.default-ttl = 300;

has Lock $!lock .= new;

# Each: { path, holder, acquired-at, ttl, expires-at }. A flat list rather than
# a path-keyed hash on purpose -- the interesting question is containment, not
# equality, so every lookup is a scan whatever the shape is.
has @!leases;
has %!waiters;
has %!pins;
has Int $!next-generation = 0;
has Int $!next-pin = 0;

submethod TWEAK {
	die X::MCP::Client.new(
		detail => 'the default-ttl of a lease table must be a positive number of seconds, not '
			~ ttl-text($!default-ttl),
	) unless usable-ttl($!default-ttl);
}

# === Acquiring ===

#|( Claim every path in C<@paths> for C<$holder>, or nothing.

    Answers C<< { granted => True, leases => [...] } >> with a plain-data
    snapshot of the leases now held for those paths, or one of three
    refusals:

      { granted => False, reason => 'conflict',
        conflicts => [ { path, leased, holder, held-for }, ... ] }

      { granted => False, reason => 'unevaluable-path', unevaluable => [ ... ] }

      { granted => False, reason => 'no-paths' }

    C<path> in a conflict is what was asked for and C<leased> is the lease
    that stood in its way — different things whenever a directory and
    something inside it collide.

    B<Never blocks and never throws.> A holder re-acquiring a path it
    already holds refreshes that lease's TTL instead of stacking a second
    one, so an agent that re-locks around a long edit keeps its claim. )
method acquire(Str:D :$holder!, :@paths!, Real :$ttl --> Hash:D) {
	# Checked before the lock is taken: none of it needs to see the table, and
	# a caller's bad argument must not be diagnosed while holding it.
	return %( granted => False, reason => 'invalid-ttl', ttl => $ttl )
		if $ttl.defined && !usable-ttl($ttl);

	return %( granted => False, reason => 'no-paths' ) unless @paths.elems;

	# A path that is not inside itself is one the lexical model cannot read at
	# all: not a string, empty, a '..' segment, a backslash, a null byte.
	my @unevaluable = @paths.grep({ path-under($_, $_) ne 'yes' }).map({ path-text($_) });
	return %( granted => False, reason => 'unevaluable-path', unevaluable => @unevaluable.List )
		if @unevaluable;

	my $life = $ttl.defined ?? $ttl !! $!default-ttl;
	my @wanted = @paths.map(*.Str).List;
	my %answer;

	$!lock.protect: {
		my $now = self!reap;
		my @conflicts;

		for @wanted -> $path {
			for @!leases -> %lease {
				next if %lease<holder> eq $holder;
				next unless overlapping($path, %lease<path>);
				@conflicts.push: %(
					path     => $path,
					leased   => %lease<path>,
					holder   => %lease<holder>,
					held-for => ($now - %lease<acquired-at>).Num,
				);
			}
		}

		if @conflicts {
			%answer = %( granted => False, reason => 'conflict', conflicts => @conflicts.List );
		}
		else {
			my @granted;
			for @wanted -> $path {
				my $held = @!leases.first({
					$_<holder> eq $holder && same-path($_<path>, $path)
				});

				if $held.defined {
					$held<acquired-at> = $now;
					$held<ttl> = $life;
					$held<expires-at> = $now + $life;
					$held<release-pending> = False;
					@granted.push: render($held, $now);
				}
				else {
					my %lease =
						:$path, :$holder,
						generation  => ++$!next-generation,
						acquired-at => $now,
						ttl         => $life,
						expires-at  => $now + $life,
						pins        => 0,
						release-pending => False,
					;
					@!leases.push: %lease;
					@granted.push: render(%lease, $now);
				}
			}

			%answer = %( granted => True, leases => @granted.List );
			self!refresh-waiters($now);
		}
	};

	%answer;
}

# === Releasing ===

#|( Give leases back. With C<paths>, exactly those of them the holder holds;
    with none — a bare C<< $table.release(:$holder) >> — everything it holds.

    Answers C<< { released => [...], not-held => [...] } >>. Releasing
    something you never held is not an error: an agent that has lost track
    of its own locks should be told so and carry on, not be refused. Paths
    are matched as the B<same location> rather than as the same string, so a
    trailing slash or a doubled separator still releases what the caller
    meant. A lease on a directory is B<not> released by naming a file inside
    it — release what you locked. )
method release(Str:D :$holder!, :@paths --> Hash:D) {
	my %answer;

	$!lock.protect: {
		self!reap;

		if @paths.elems {
			my @released;
			my @missing;

			for @paths -> $wanted {
				my $held = ($wanted ~~ Str:D)
					?? @!leases.first({ $_<holder> eq $holder && same-path($_<path>, $wanted) })
					!! Any;

				if $held.defined {
					@released.push: $held<path>;
					if $held<pins> > 0 {
						$held<release-pending> = True;
					}
					else {
						@!leases = @!leases.grep({
							!($_<holder> eq $holder && same-path($_<path>, $wanted))
						}).Array;
					}
				}
				else {
					@missing.push: path-text($wanted);
				}
			}

			%answer = %( released => @released.List, not-held => @missing.List );
		}
		else {
			my @mine = @!leases.grep({ $_<holder> eq $holder }).map({ $_<path> }).List;
			for @!leases.grep({ $_<holder> eq $holder && $_<pins> > 0 }) -> %lease {
				%lease<release-pending> = True;
			}
			@!leases = @!leases.grep({
				$_<holder> ne $holder || $_<pins> > 0
			}).Array;
			%answer = %( released => @mine.List, not-held => ().List );
		}
		self!refresh-waiters(now);
	};

	%answer;
}

#| Request release of everything one holder has, and answer how many leases
#| that was. A generation pinned by provider code stays present, marked
#| release-pending, until its final pin returns. The drained-run and cancel
#| path: an agent that has stopped running cannot be relied on to tidy up.
method release-holder(Str:D $holder --> Int:D) {
	my Int $count = 0;

	$!lock.protect: {
		self!reap;
		$count = @!leases.grep({ $_<holder> eq $holder }).elems;
		for @!leases.grep({ $_<holder> eq $holder && $_<pins> > 0 }) -> %lease {
			%lease<release-pending> = True;
		}
		@!leases = @!leases.grep({
			$_<holder> ne $holder || $_<pins> > 0
		}).Array;
		%!waiters = %!waiters.pairs.grep({ .value<holder> ne $holder }).Hash;
		self!refresh-waiters(now);
	};

	$count;
}

#| Request release of the whole table, and answer how many leases were in it.
#| Pinned generations remain release-pending until their provider calls return.
#| The engine's shutdown path must treat a non-empty status after this as an
#| incomplete drain, never as successful cleanup.
method release-all(--> Int:D) {
	my Int $count = 0;

	$!lock.protect: {
		self!reap;
		$count = @!leases.elems;
		for @!leases.grep({ $_<pins> > 0 }) -> %lease {
			%lease<release-pending> = True;
		}
		@!leases = @!leases.grep({ $_<pins> > 0 }).Array;
		%!waiters = ();
	};

	$count;
}

# === Waiting and in-flight mutation pins ===

# Atomically retry an acquisition and, when it is still blocked, publish the
# wait-for edges used for diagnostics and cycle refusal. The caller owns the
# sleep; this method never waits while holding the table lock.
method wait-attempt(
	Str:D :$waiter-id!, Str:D :$holder!, :@paths!, Real :$ttl,
	Bool:D :$allow-hold = True,
	--> Hash:D
) {
	return %( granted => False, reason => 'invalid-ttl', ttl => $ttl )
		if $ttl.defined && !usable-ttl($ttl);
	return %( granted => False, reason => 'no-paths' ) unless @paths.elems;
	my @unevaluable = @paths.grep({ path-under($_, $_) ne 'yes' }).map({ path-text($_) });
	return %( granted => False, reason => 'unevaluable-path', unevaluable => @unevaluable.List )
		if @unevaluable;

	my @wanted = @paths.map(*.Str).List;
	my $life = $ttl.defined ?? $ttl !! $!default-ttl;
	my %answer;
	$!lock.protect: {
		my $now = self!reap;
		my @conflicts = self!conflicts($holder, @wanted, $now);
		if !@conflicts {
			%!waiters{$waiter-id}:delete;
			%answer = self!grant($holder, @wanted, $life, $now);
			self!refresh-waiters($now);
		}
		elsif !$allow-hold && @!leases.first({ $_<holder> eq $holder }).defined {
			%!waiters{$waiter-id}:delete;
			%answer = %(
				granted => False, reason => 'hold-and-wait',
				conflicts => @conflicts.List,
			);
		}
		else {
			my @blockers = @conflicts.map(*<holder>).unique.sort.List;
			%!waiters{$waiter-id} = %(
				id => $waiter-id, :$holder, paths => @wanted.List, ttl => $life,
				registered-at => (%!waiters{$waiter-id}<registered-at> // $now),
				blockers => @blockers,
			);
			my @cycle = self!cycle-from($holder);
			if @cycle {
				%!waiters{$waiter-id}:delete;
				%answer = %(
					granted => False, reason => 'deadlock',
					conflicts => @conflicts.List, cycle => @cycle.List,
				);
			}
			else {
				%answer = %(
					granted => False, reason => 'conflict',
					conflicts => @conflicts.List, blockers => @blockers,
				);
			}
		}
	};
	%answer;
}

method cancel-wait(Str:D $waiter-id --> Bool:D) {
	$!lock.protect: { so %!waiters{$waiter-id}:delete };
}

# Pin the exact covering lease generations before a provider call starts.
# Expiry and explicit release become pending until the last pin is returned.
method pin(Str:D :$holder!, :@paths! --> Hash:D) {
	return %( pinned => False, reason => 'no-paths' ) unless @paths.elems;
	my %answer;
	$!lock.protect: {
		my $now = self!reap;
		my @selected;
		my $missing;
		for @paths -> $path {
			my $lease = @!leases.first({
				$_<holder> eq $holder && path-under($_<path>, $path.Str) eq 'yes'
			});
			unless $lease.defined {
				$missing = $path.Str;
				last;
			}
			@selected.push($lease) unless @selected.first({
				$_<generation> == $lease<generation>
			});
		}

		if $missing.defined {
			%answer = %( pinned => False, reason => 'not-held', path => $missing );
		}
		else {
			my $token = 'pin-' ~ ++$!next-pin;
			$_<pins>++ for @selected;
			%!pins{$token} = %(
				holder => $holder,
				generations => @selected.map(*<generation>).List,
				pinned-at => $now,
			);
			%answer = %( pinned => True, :$token );
		}
	};
	%answer;
}

method unpin(Str:D $token --> Bool:D) {
	my Bool $found = False;
	$!lock.protect: {
		my $pin = %!pins{$token}:delete;
		if $pin.defined {
			$found = True;
			my @generations = $pin<generations>.list;
			for @!leases -> %lease {
				next unless @generations.first(* == %lease<generation>).defined;
				%lease<pins>-- if %lease<pins> > 0;
			}
			self!reap;
		}
	};
	$found;
}

# One status call so a host does not assemble mutually inconsistent snapshots.
method status(--> Hash:D) {
	my %status;
	$!lock.protect: {
		my $now = self!reap;
		%status = %(
			leases => @!leases.map({
				%( |render($_, $now), pins => $_<pins>,
					release-pending => ?$_<release-pending> )
			}).List,
			waiters => %!waiters.values.sort(*<id>).map({
				%(
					id => $_<id>, holder => $_<holder>, paths => $_<paths>.List,
					blockers => $_<blockers>.List,
					waiting-for => ($now - $_<registered-at>).Num,
				)
			}).List,
			pins => %!pins.map({
				%(
					token => .key, holder => .value<holder>,
					generations => .value<generations>.List,
					pinned-for => ($now - .value<pinned-at>).Num,
				)
			}).sort(*<token>).List,
		);
	};
	%status;
}

# === Asking ===

#|( What C<$holder> may do to C<$path> right now:

      { verdict => 'own',     leased, holder, held-for }   # a lease of mine covers it
      { verdict => 'other',   leased, holder, held-for }   # somebody else is on it
      { verdict => 'unknown', leased, holder }             # not mine, and not comparable
      { verdict => 'free' }                                # nobody has claimed it

    C<other> is decided before C<own>, so a table that somehow held both
    answers at once (it cannot: C<acquire> checks both directions before it
    grants) refuses rather than permits.

    C<unknown> means only that some B<other> holder's lease could not be
    compared with this path lexically. A path that is unusable on its own
    terms, with nobody else's lease anywhere near it, is C<free> — there is
    nothing for a lease to protect it from, and the caller's own
    fail-closed rules decide what an unreadable argument is worth. )
method covering(Str:D :$holder!, Str :$path --> Hash:D) {
	return %( verdict => 'unknown' ) unless $path ~~ Str:D;

	my %answer;

	$!lock.protect: {
		my $now = self!reap;

		my $mine;
		my $other;
		my $unknown;

		for @!leases -> %lease {
			if %lease<holder> eq $holder {
				$mine //= %lease if path-under(%lease<path>, $path) eq 'yes';
				next;
			}

			my $down = path-under(%lease<path>, $path);
			my $up = path-under($path, %lease<path>);

			if $down eq 'yes' || $up eq 'yes' {
				$other //= %lease;
			}
			elsif $down eq 'unknown' || $up eq 'unknown' {
				$unknown //= %lease;
			}
		}

		%answer = do if $other.defined {
			%(
				verdict  => 'other',
				leased   => $other<path>,
				holder   => $other<holder>,
				held-for => ($now - $other<acquired-at>).Num,
			);
		}
		elsif $mine.defined {
			%(
				verdict  => 'own',
				leased   => $mine<path>,
				holder   => $holder,
				held-for => ($now - $mine<acquired-at>).Num,
			);
		}
		elsif $unknown.defined {
			%( verdict => 'unknown', leased => $unknown<path>, holder => $unknown<holder> );
		}
		else {
			%( verdict => 'free' );
		}
	};

	%answer;
}

#| Every live lease, as deep plain-data copies, in the order they were taken:
#| what a status surface renders. Expired leases are reaped on the way past, so
#| this is also the cheapest way to tidy a table nobody has asked anything of
#| in a while.
method leases(--> List:D) {
	my @snapshot;

	$!lock.protect: {
		my $now = self!reap;
		@snapshot = @!leases.map({ render($_, $now) });
	};

	@snapshot.List;
}

# === Internals ===

# Drop everything whose time is up, and answer the `now` the caller should
# measure against -- one reading of the clock per operation, so two leases taken
# in one call cannot disagree about when they were taken. Called with the lock
# held, always.
method !reap(--> Instant:D) {
	my $now = now;
	@!leases = @!leases.grep({
		($_<expires-at> > $now && !$_<release-pending>) || $_<pins> > 0
	}).Array;
	self!refresh-waiters($now);
	$now;
}

# Recompute rather than decrement edges: one directory lease can cover many
# requested paths and release/expiry can invalidate several blockers at once.
# Called only with $!lock held.
method !refresh-waiters(Instant:D $now --> Nil) {
	for %!waiters.values -> %waiter {
		%!waiters{%waiter<id>}<blockers> = self!conflicts(
			%waiter<holder>, %waiter<paths>.list, $now,
		).map(*<holder>).unique.sort.List;
	}
}

# Called only while $!lock is held.
method !conflicts(Str:D $holder, @wanted, Instant:D $now --> List:D) {
	my @conflicts;
	for @wanted -> $path {
		for @!leases -> %lease {
			next if %lease<holder> eq $holder;
			next unless overlapping($path, %lease<path>);
			@conflicts.push: %(
				path => $path, leased => %lease<path>, holder => %lease<holder>,
				held-for => ($now - %lease<acquired-at>).Num,
			);
		}
	}
	@conflicts.List;
}

# Called only while $!lock is held.
method !grant(Str:D $holder, @wanted, Real:D $life, Instant:D $now --> Hash:D) {
	my @granted;
	for @wanted -> $path {
		my $held = @!leases.first({
			$_<holder> eq $holder && same-path($_<path>, $path)
		});
		if $held.defined {
			$held<acquired-at> = $now;
			$held<ttl> = $life;
			$held<expires-at> = $now + $life;
			$held<release-pending> = False;
			@granted.push: render($held, $now);
		}
		else {
			my %lease =
				:$path, :$holder, generation => ++$!next-generation,
				acquired-at => $now, ttl => $life, expires-at => $now + $life,
				pins => 0, release-pending => False,
			;
			@!leases.push: %lease;
			@granted.push: render(%lease, $now);
		}
	}
	%( granted => True, leases => @granted.List );
}

# Return a holder cycle beginning and ending at $start, or an empty list. A
# holder may have more than one wait entry, so adjacency is unioned by holder.
method !cycle-from(Str:D $start --> List:D) {
	my %edges;
	for %!waiters.values -> %waiter {
		%edges{%waiter<holder>} //= [];
		%edges{%waiter<holder>}.append: %waiter<blockers>.list;
	}
	my %visiting;
	my @path;
	my @found;
	my sub visit(Str:D $node --> Bool:D) {
		return False if %visiting{$node}:exists && !%visiting{$node};
		if %visiting{$node}:exists {
			my $at = @path.first($node, :k) // 0;
			@found = (|@path[$at .. *], $node);
			return True;
		}
		%visiting{$node} = True;
		@path.push: $node;
		for (%edges{$node} // []).list.unique -> $next {
			return True if visit($next.Str);
		}
		@path.pop;
		%visiting{$node} = False;
		False;
	}
	visit($start);
	@found.List;
}

# Whether two paths collide: either contains the other, or the pair cannot be
# compared at all. Unknown is a collision -- see the fail-closed note in the Pod.
my sub overlapping(Str:D $a, Str:D $b --> Bool:D) {
	so path-under($a, $b) ne 'no' || path-under($b, $a) ne 'no';
}

# Whether two strings name the same location: containment both ways. The lexical
# parser rather than string equality, so '/srv/src', '/srv/src/' and '/srv//src'
# are one path -- which is what a model that wrote the same lock twice, slightly
# differently, meant.
my sub same-path(Str:D $a, Str:D $b --> Bool:D) {
	path-under($a, $b) eq 'yes' && path-under($b, $a) eq 'yes';
}

# Bool is an Int and would otherwise pass as a number of seconds.
my sub usable-ttl($ttl --> Bool:D) {
	so $ttl ~~ Real:D && !($ttl ~~ Bool) && $ttl > 0;
}

my sub ttl-text($ttl --> Str:D) {
	$ttl.defined ?? $ttl.gist !! 'an undefined ' ~ $ttl.^name;
}

# A path as an error message should show it. Anything that is not a string is
# named by its type: rendering the gist of an arbitrary object into a message a
# model will read is how a lock error becomes a prompt injection.
my sub path-text($value --> Str:D) {
	return $value.Str if $value ~~ Str:D;
	$value.defined ?? '(a ' ~ $value.^name ~ ')' !! '(undefined)';
}

# One lease, as a caller may keep it: a fresh hash of immutable values, with the
# two numbers a status surface actually wants worked out already.
my sub render(%lease, Instant:D $now --> Hash:D) {
	%(
		path        => %lease<path>,
		holder      => %lease<holder>,
		acquired-at => %lease<acquired-at>,
		ttl         => %lease<ttl>,
		expires-at  => %lease<expires-at>,
		held-for    => ($now - %lease<acquired-at>).Num,
		expires-in  => (%lease<expires-at> - $now).Num,
	);
}
