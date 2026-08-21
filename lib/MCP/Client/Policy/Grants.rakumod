=begin pod

=head1 NAME

MCP::Client::Policy::Grants - the session grant book a fleet of agents share

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Policy;
use MCP::Client::Policy::Grants;

# One store for the whole session, seeded from what the last session remembered.
my $grants = MCP::Client::Policy::Grants.new(grants => $session.grants);

my $parent = MCP::Client::Policy.new(:$provider, :&on-ask, grants-store => $grants);
my $child  = MCP::Client::Policy.new(:$provider, :&on-ask, grants-store => $grants);

# The human says "always allow" on the parent's question ...
$grants.list.elems;      # 1

# ... and the child never asks that question at all.
=end code

=head1 DESCRIPTION

A session grant — the rule an C<always-allow> or C<always-deny> answer leaves
behind — belongs to the B<human>, not to the object that happened to ask the
question. A single agent cannot tell the difference, because there is only one
policy. A fleet can: ten children, each with its own
L<MCP::Client::Policy|lib/MCP/Client/Policy.rakumod>, will ask the same
question ten times if each of them remembers the answer privately.

This is the shared answer to that: a small, lock-protected list of rules that
any number of policies consult and any of them can add to. Give the same store
to every policy in a session and the doctrine becomes B<one session, one grant
set> — the human says "always" once, and every agent alive at that moment, plus
every agent started afterwards, is bound by it.

=head2 What it does not change

A store is a place to keep grants, not a new kind of permission. Everything
about how a grant is B<used> stays where it was, in the policy:

=item grants are consulted B<only after the static rules have said C<ask>>, so
      a grant can never overrule a C<deny> rule, and never overrules the danger
      floor;
=item among the rules that do get consulted, the same precedence applies —
      B<deny E<gt> ask E<gt> allow> — so a deny grant beats an allow grant
      whichever policy made either of them;
=item a rule is validated before it is kept, by exactly the validator the
      policy's own rules go through.

=head2 Live, not snapshotted

Policies read the store on every decision rather than copying it at
construction, so a grant made a millisecond ago through one policy is in force
for the next call through another. This is the whole point: a fleet unblocks
the moment the human answers, not at the next agent's next start-up.

=head2 Thread safety

One lock, held only across the list. Everything that comes out is a deep
plain-data copy, so a caller may keep and edit a snapshot — persist it, render
it, diff it — without the store moving underneath it or the caller's edits
reaching back in.

=head1 EXAMPLES

Seeding a resumed session, then persisting whatever it learns:

=begin code :lang<raku>
my $grants = MCP::Client::Policy::Grants.new(grants => from-json(slurp 'grants.json'));

my $policy = MCP::Client::Policy.new(
    :$provider, :&on-ask,
    grants-store => $grants,
    on-grant     => -> @all { spurt 'grants.json', to-json(@all) },
);
=end code

Adding a grant nobody was asked about — a preset that starts a session already
trusting a directory, say. C<add> takes a list, validates every rule in it, and
appends them in order:

=begin code :lang<raku>
$grants.add([
    { tool => 'fs_write', decision => 'allow', under => '/srv/scratch' },
    { tool => 'fs_edit',  decision => 'allow', under => '/srv/scratch' },
]);
=end code

A rule that will not validate throws, and B<nothing> is added — a half-applied
list of grants would leave a session trusting something the caller never
described:

=begin code :lang<raku>
$grants.add([{ tool => 'fs_write', decision => 'allow', under => '/a/../b' }]);
# X::MCP::Client: invalid under '/a/../b' in a session grant for 'fs_write' ...
say $grants.list.elems;   # unchanged
=end code

=head1 SEE ALSO

L<MCP::Client::Policy|lib/MCP/Client/Policy.rakumod> — the C<grants-store>
option, and what a grant means once it is in the book.

=end pod

use MCP::Client::Exceptions;
use MCP::Client::Policy::Rules;

unit class MCP::Client::Policy::Grants;

has Lock $!lock .= new;
has      @!grants;

submethod TWEAK(:$grants, *%unknown) {
	my @unknown = %unknown.keys.sort;
	die X::MCP::Client.new(
		detail => "unknown option(s) for a grant store: '{@unknown.join(q{', '})}'; a grant store "
			~ 'is made of grants',
	) if @unknown;

	@!grants = validate-rules($grants, what => 'session grant');
}

#|( Add rules to the book, in order, and answer the whole book as it now
    stands (deep plain-data copies, exactly as C<list> renders it).

    Every rule is validated first, by the policy's own rule validator: a list
    with one bad rule in it throws an C<X::MCP::Client> and adds B<none> of
    them, so the book never ends up holding half of what a caller meant. An
    empty list is not an error and adds nothing.

    Duplicates are kept rather than collapsed. Two identical grants decide
    every call identically, and a book that quietly dropped one would be a
    book whose C<list> did not round-trip what it was given. )
method add(@rules --> List:D) {
	my @validated = @rules.map({ validate-rule($_, what => 'session grant') });

	my @snapshot;
	$!lock.protect: {
		@!grants.append: @validated;
		@snapshot = @!grants.map({ plain-copy($_) });
	};

	@snapshot.List;
}

#| Every grant in the book, in the order it was made, as deep plain-data
#| copies: what a policy decides against, what a session persists, and what a
#| UI renders. Editing what comes back changes nothing.
method list(--> List:D) {
	$!lock.protect: { @!grants.map({ plain-copy($_) }).List };
}

#| How many grants are in the book. The cheap question, for a status surface
#| that only wants to say whether the session has learned anything.
method elems(--> Int:D) {
	$!lock.protect: { @!grants.elems };
}

# === Helpers ===

# A deep copy of plain data, as MCP::Client::Policy makes one: a snapshot must
# never be a window onto the book's own state.
my sub plain-copy($value) {
	return $value.Hash.map({ $_.key => plain-copy($_.value) }).Hash if $value ~~ Associative;
	return $value.list.map({ plain-copy($_) }).List if $value ~~ Positional;
	$value;
}
