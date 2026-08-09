=begin pod

=head1 NAME

MCP::Client::Correlator - the pending-request table for one MCP connection

=head1 DESCRIPTION

A stdio MCP server is one pipe carrying every conversation at once: requests go
down it in whatever order the caller made them, and answers come back in
whatever order the server finished them. The correlator is the bookkeeping that
makes that usable — it hands out ids, hands back a C<Promise> per request, and
matches each inbound answer to the promise that is waiting for it.

Everything it does is thread-safe, and it is careful about I<how>. All table
mutation happens under a lock, but no C<Promise> is ever kept or broken while
that lock is held: the vows are collected inside the lock and settled outside
it. A continuation that runs on the settling thread therefore cannot re-enter
the correlator and deadlock — the same defer-mutations-during-a-walk discipline
used elsewhere in this tree.

=head2 Time is injectable

C<&.now> and C<&.schedule-after> exist so timeouts can be tested without
sleeping. Override both with a virtual clock and a timer you fire by hand, and
a test for "this request timed out after sixty seconds" runs in microseconds
and never flakes on a loaded CI box.

=head2 Late answers

A request that times out, is cancelled, or is failed by C<fail-all> is removed
from the table there and then. If the server answers it afterwards, C<resolve>
returns C<False> and the answer is dropped — a promise is only settled once,
and the caller has already been told what happened.

=head1 EXAMPLES

The shape a transport uses it in:

=begin code :lang<raku>
use MCP::Client::Correlator;

my $correlator = MCP::Client::Correlator.new(default-timeout => 30);

# Sending side
my $id = $correlator.next-id;
my $answer = $correlator.register($id, method => 'tools/call', timeout => 10);
$proc.print(format-message(build-request($id, 'tools/call', %args, :era<modern>)));

# Receiving side, on the read loop
given parse-inbound($line) -> %in {
	if %in<kind> eq 'response' {
		%in<error>:exists
			?? $correlator.reject(%in<id>, X::MCP::Client::Protocol.new(
					detail => %in<error><message> // 'server error',
					code   => %in<error><code>,
					data   => %in<error><data>,
				))
			!! $correlator.resolve(%in<id>, normalize-result(%in<result>));
	}
}

my %result = await $answer;   # or throws whichever failure got there first
=end code

When the child dies, everyone waiting hears about it at once, and anything
registered afterwards fails immediately instead of hanging forever:

=begin code :lang<raku>
$correlator.fail-all(X::MCP::Client::ServerGone.new(
	exit-code => $proc-exit, stderr-tail => $tail,
));
say $correlator.closed;                          # True
await $correlator.register(99);                  # throws ServerGone straight away
=end code

Timeouts under a virtual clock:

=begin code :lang<raku>
my @timers;
my $c = MCP::Client::Correlator.new(
	now            => { 0 },
	schedule-after => -> Real $s, &cb { @timers.push($s => &cb); Promise.kept },
);

my $p = $c.register(1, timeout => 5);
@timers[0].value.();                             # fire the timer by hand
say $p.status;                                   # Broken
say $p.cause ~~ X::MCP::Client::Timeout;         # True
=end code

=end pod

use MCP::Client::Exceptions;

unit class MCP::Client::Correlator;

#| Injectable clock, used to stamp registrations so a caller can ask how long a
#| request has been outstanding. Override in tests for determinism.
has &.now = { now };

#| Injectable timer. Called as C<schedule-after($seconds, &cb)> and expected to
#| run C<&cb> after that many seconds; the return value is ignored. Override in
#| tests to capture the requested delay and fire the callback by hand.
has &.schedule-after = -> Real $s, &cb { Promise.in($s).then(&cb) };

#| Timeout applied by C<register> when the caller names none. C<0> (or a
#| negative number) means "wait forever", which is what a caller wants for a
#| request whose cancellation it is managing itself.
has Real:D $.default-timeout = 60;

has Lock      $!lock .= new;
has           %!pending;
has Int       $!next-id = 0;
has Int       $!serial = 0;
has Exception $!failure;

#| The next request id for this connection. Ids start at 1 and never repeat,
#| so a late answer to a long-dead request can never be mistaken for the answer
#| to a live one.
method next-id(--> Int:D) {
	$!lock.protect: { ++$!next-id }
}

#| Register a request and get back the Promise that will carry its answer.
#|
#| The promise is kept with whatever C<resolve> is given, or broken with the
#| exception from C<reject>/C<cancel>/C<fail-all>, or broken with an
#| X::MCP::Client::Timeout once C<$timeout> seconds have passed. A timeout of
#| C<0> disables the timer.
#|
#| C<$method> is remembered only so failures can name the call that produced
#| them; the correlator never looks at it otherwise.
#|
#| Dies with X::MCP::Client::Protocol on an undefined id, or on an id that is
#| already in flight — both are caller bugs, and silently letting the second
#| registration shadow the first would lose an answer.
method register($id, Str :$method, Real :$timeout = $!default-timeout --> Promise:D) {
	die X::MCP::Client::Protocol.new(detail => 'cannot register a request with no id')
		unless $id.defined;

	my $promise = Promise.new;
	my $vow = $promise.vow;
	my Int $token;
	my Exception $failure;

	$!lock.protect: {
		$failure = $!failure;
		without $failure {
			die X::MCP::Client::Protocol.new(
				detail => "request id '$id' is already in flight",
			) if %!pending{$id}:exists;

			$token = ++$!serial;
			%!pending{$id} = {
				:$vow, :$token, :$method, started => &!now.(),
			};
		}
	}

	# Registering against a correlator whose connection has already failed is
	# not an error — it is a race every client loses sooner or later — so it
	# fails the one request rather than throwing at the caller.
	with $failure {
		$vow.break($failure);
		return $promise;
	}

	if $timeout.defined && $timeout > 0 {
		&!schedule-after.($timeout, { self!expire($id, $token, $timeout) });
	}

	$promise;
}

#| Deliver an answer. Returns False when nothing was waiting for that id, which
#| is the normal fate of an answer to a request that already timed out; the
#| caller logs it and carries on rather than treating it as an error.
method resolve($id, $value --> Bool:D) {
	my $vow = self!claim($id);
	return False without $vow;
	$vow.keep($value);
	True;
}

#| Fail one outstanding request. Returns False when nothing was waiting.
method reject($id, Exception:D $error --> Bool:D) {
	my $vow = self!claim($id);
	return False without $vow;
	$vow.break($error);
	True;
}

#| Abandon one outstanding request. The promise is broken with
#| X::MCP::Client::Cancelled unless the caller supplies its own exception, and
#| the id stops being tracked immediately, so a late answer is dropped.
method cancel($id, Exception $error? --> Bool:D) {
	my $method = self.method-for($id);
	self.reject($id, $error // X::MCP::Client::Cancelled.new(:$id, :$method));
}

#| Fail every outstanding request with the same exception — what a transport
#| does when the connection underneath it dies.
#|
#| By default this also closes the correlator: C<closed> becomes True and every
#| later C<register> comes back already broken with C<$error>, so a caller that
#| keeps making requests against a dead server fails fast instead of hanging.
#| Pass C<:!close> to fail the current work without retiring the table.
#|
#| Returns the number of requests that were failed.
method fail-all(Exception:D $error, Bool:D :$close = True --> Int:D) {
	my @vows;
	$!lock.protect: {
		@vows = %!pending.values.map({ .<vow> }).List;
		%!pending = ();
		$!failure //= $error if $close;
	}
	.break($error) for @vows;
	@vows.elems;
}

#| True once C<fail-all> has retired the table.
method closed(--> Bool:D) {
	$!lock.protect: { $!failure.defined }
}

#| The exception a closed correlator fails new registrations with, or Nil.
method failure() {
	$!lock.protect: { $!failure }
}

#| How many requests are outstanding.
method pending-count(--> Int:D) {
	$!lock.protect: { %!pending.elems }
}

#| The ids of the outstanding requests, as strings (a Hash key always is one).
method pending-ids(--> List:D) {
	$!lock.protect: { %!pending.keys.sort.List }
}

#| The method name registered for an outstanding id, or Nil.
method method-for($id --> Str) {
	$!lock.protect: {
		(%!pending{$id}:exists) ?? %!pending{$id}<method> !! Str;
	}
}

#| How long an outstanding request has been waiting, measured with C<&.now>,
#| or Nil if it is not outstanding.
method age-of($id) {
	my $started = $!lock.protect: {
		(%!pending{$id}:exists) ?? %!pending{$id}<started> !! Nil;
	};
	$started.defined ?? &!now.() - $started !! Nil;
}

# Take an id out of the table and return the vow that was waiting on it (or
# Nil). Every settling path goes through here, so "removed from the table" and
# "about to be settled" are the same instant, under the lock.
method !claim($id) {
	$!lock.protect: {
		my $vow = Nil;
		if %!pending{$id}:exists {
			$vow = %!pending{$id}<vow>;
			%!pending{$id}:delete;
		}
		$vow;
	}
}

# Fired by the injected timer. The token guards against a stale timer killing a
# newer request: ids handed out by next-id never repeat, but a caller supplying
# its own ids may well reuse one after the first has been answered.
method !expire($id, Int $token, Real $timeout) {
	my $vow;
	my $method;
	$!lock.protect: {
		if (%!pending{$id}:exists) && %!pending{$id}<token> == $token {
			$vow = %!pending{$id}<vow>;
			$method = %!pending{$id}<method>;
			%!pending{$id}:delete;
		}
	}
	with $vow {
		.break(X::MCP::Client::Timeout.new(:$id, :$method, seconds => $timeout));
	}
}
