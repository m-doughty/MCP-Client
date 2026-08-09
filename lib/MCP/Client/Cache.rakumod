=begin pod

=head1 NAME

MCP::Client::Cache - the ttlMs/cacheScope cache for modern-era results

=head1 DESCRIPTION

The 2026-07-28 protocol has no session, so a client re-asks for the catalog
every time it needs it — which for an agent loop is constantly. In exchange the
server tells the client how long an answer stays good: a cacheable result
carries C<ttlMs> (how many milliseconds it may be reused for) and
C<cacheScope> (C<public> or C<private>). This class is the client side of that
bargain.

Only four results are cacheable at all: C<tools/list>, C<prompts/list>,
C<resources/list> and C<resources/read>. Three rules keep it honest, and each
one is enforced here rather than left to the caller:

=item B<No C<ttlMs>, no storage.> A result that does not say it is cacheable is
      not cacheable. C<ttlMs> of C<0> means exactly that, and is what a server
      says about a resource whose contents it cannot vouch for.
=item B<Legacy results are never stored.> The 2025-11-25 era has no cache
      metadata at all, so there is no TTL to honour and nothing legitimises
      reuse; C<put> refuses them outright.
=item B<Expiry is by the clock, not by hope.> An entry is dropped the first
      time it is asked for after its TTL runs out.

C<cacheScope> is recorded and readable through C<scope-of>, but does not change
whether an entry is stored: this cache lives inside one client, for one user,
and never hands anything to a third party, so C<private> results are as
cacheable here as C<public> ones. A shared or proxying front-end would have to
look at the scope; that is the point of recording it.

=head2 Time is injectable

C<&.now> makes expiry testable without sleeping. Pass a closure over a variable
you increment by hand and a test for "this entry expires after thirty seconds"
runs instantly and deterministically.

=head1 EXAMPLES

The shape a client uses it in:

=begin code :lang<raku>
use MCP::Client::Cache;

my $cache = MCP::Client::Cache.new;

method list-tools(Bool :$refresh) {
	my $key = $cache.key-for('tools/list');
	my $hit = $cache.get($key, :$refresh);
	return $hit<tools>.List if $hit.defined;

	my %result = self!request('tools/list');
	$cache.put($key, %result, era => self.era);   # a no-op on a legacy server
	%result<tools>.List;
}
=end code

Keys are built from the method and its parameters, so two reads of different
resources cannot collide and parameter order cannot matter:

=begin code :lang<raku>
my $a = $cache.key-for('resources/read', { uri => 'file:///a', extra => 1 });
my $b = $cache.key-for('resources/read', { extra => 1, uri => 'file:///a' });
say $a eq $b;    # True
=end code

Expiry under a virtual clock:

=begin code :lang<raku>
my $clock = 0;
my $cache = MCP::Client::Cache.new(now => { $clock });

$cache.put('tools/list', { tools => [], ttlMs => 30_000, cacheScope => 'public' });
say $cache.get('tools/list').defined;    # True
say $cache.scope-of('tools/list');       # public

$clock = 29;
say $cache.get('tools/list').defined;    # True
$clock = 31;
say $cache.get('tools/list').defined;    # False — and the entry is gone
say $cache.elems;                        # 0
=end code

=end pod

use JSON::Fast;

unit class MCP::Client::Cache;

#| Injectable clock. Anything that returns a number that grows with time will
#| do — the cache only ever compares its own readings with each other.
has &.now = { now };

has Lock $!lock .= new;
has      %!entries;

#| A stable cache key for a method and its parameters. Parameters are rendered
#| with sorted keys, so a key depends on what was asked for and not on the
#| order the caller happened to write it in.
method key-for(Str:D $method, %params = {} --> Str:D) {
	return $method unless %params.elems;
	$method ~ "\0" ~ to-json(%params, :!pretty, :sorted-keys);
}

#| Store a result if — and only if — the server said it may be stored. Returns
#| True when it was stored, False when it was refused, so a caller can log the
#| difference without re-deriving the rules.
#|
#| C<$era> exists to make the legacy rule impossible to forget: pass the era
#| the result came back in, and legacy results are refused without the caller
#| having to remember why.
method put(Str:D $key, $result, Str:D :$era = 'modern' --> Bool:D) {
	return False unless $era eq 'modern';
	return False unless $result ~~ Associative;

	my %result = $result.Hash;
	my $ttl-ms = %result<ttlMs>;
	return False unless $ttl-ms ~~ Real:D && $ttl-ms > 0;

	my $scope = %result<cacheScope> ~~ Str:D ?? %result<cacheScope> !! 'private';
	my $stored-at = &!now.();

	$!lock.protect: {
		%!entries{$key} = {
			value => %result,
			scope => $scope,
			ttl-ms => $ttl-ms,
			stored-at => $stored-at,
			expires => $stored-at + $ttl-ms / 1000,
		};
	}

	True;
}

#| The stored result for a key, or Nil when there is none, when the one there
#| has expired (it is dropped on the way past), or when C<:refresh> was asked
#| for.
#|
#| C<:refresh> also evicts: a caller asking for fresh data is about to fetch
#| it, and leaving the stale copy behind only invites something else to serve
#| it in the meantime.
#|
#| The result is the stored structure itself, not a copy — deep-cloning a tool
#| catalogue on every hit would cost more than the cache saves. Treat what
#| comes back as read-only; mutating it mutates every later hit.
method get(Str:D $key, Bool:D :$refresh = False) {
	if $refresh {
		self.invalidate($key);
		return Nil;
	}

	my $value = Nil;
	$!lock.protect: {
		if %!entries{$key}:exists {
			my %entry = %!entries{$key};
			if &!now.() >= %entry<expires> {
				%!entries{$key}:delete;
			}
			else {
				$value = %entry<value>;
			}
		}
	}
	$value;
}

#| The C<cacheScope> a stored entry came with, or Nil. Expired entries answer
#| Nil, exactly as C<get> does, but are left for C<get> or C<purge-expired> to
#| clear: asking about an entry is not using it.
method scope-of(Str:D $key --> Str) {
	$!lock.protect: {
		my $scope = Str;
		if %!entries{$key}:exists {
			my %entry = %!entries{$key};
			$scope = %entry<scope> if &!now.() < %entry<expires>;
		}
		$scope;
	}
}

#| Drop one entry. Returns True if there was one.
method invalidate(Str:D $key --> Bool:D) {
	$!lock.protect: {
		my $had = %!entries{$key}:exists;
		%!entries{$key}:delete if $had;
		$had;
	}
}

#| Drop every entry — what a client does when it reconnects, since the new
#| server has made none of the old server's promises.
method clear(--> Int:D) {
	$!lock.protect: {
		my $n = %!entries.elems;
		%!entries = ();
		$n;
	}
}

#| Drop every entry whose TTL has run out. Nothing needs this for correctness
#| (C<get> expires lazily); it is here so a long-lived client can stop paying
#| for keys nobody asks about any more. Returns the number dropped.
method purge-expired(--> Int:D) {
	$!lock.protect: {
		my $at = &!now.();
		# Collect first, delete after: mutating the hash while walking its own
		# keys is the bug this pattern exists to avoid.
		my Str @dead = %!entries.keys.grep({ %!entries{$_}<expires> <= $at });
		%!entries{$_}:delete for @dead;
		@dead.elems;
	}
}

#| How many entries are stored, expired ones included.
method elems(--> Int:D) {
	$!lock.protect: { %!entries.elems }
}

#| The stored keys, expired ones included, sorted.
method keys-stored(--> List:D) {
	$!lock.protect: { %!entries.keys.sort.List }
}
