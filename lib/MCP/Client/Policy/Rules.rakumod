=begin pod

=head1 NAME

MCP::Client::Policy::Rules - the permission engine: plain data in, a decision out

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Policy::Rules;

my @rules =
	{ tool => 'fs_read',  decision => 'allow' },
	{ tool => 'fs_write', decision => 'allow', under => '/srv/scratch' },
	{ tool => 'fs_*',     decision => 'deny',  under => '/srv/secrets' },
;

evaluate(@rules, 'fs_write', { path => '/srv/scratch/notes.md' },
	roots => { fs => '/srv' });
# { decision => 'allow', reason => 'rule', rule => {...},
#   paths => ('/srv/scratch/notes.md',),
#   suggestion => { tool => 'fs_write', under => '/srv/scratch' } }

evaluate(@rules, 'fs_write', { path => '../../etc/passwd' },
	roots => { fs => '/srv' });
# { decision => 'ask', reason => 'unevaluable-path', ... }
=end code

=head1 DESCRIPTION

The half of C<MCP::Client::Policy> that has no state, no locks, no provider and
no user: a list of rules, the name of a tool, the arguments a model asked to
call it with, and out comes one of C<allow>, C<deny> or C<ask> together with
everything a permission prompt needs in order to explain itself. Keeping it
separate is what makes the interesting part testable — every path in here is
reachable from a single function call with plain data.

=head2 A rule

A rule is JSON-safe plain data with two required members and a handful of
optional narrowers:

=begin code :lang<raku>
{ tool => 'fs_read', decision => 'allow' }                        # bare
{ tool => 'fs_*',    decision => 'deny', under => '/etc' }        # narrowed by path
{ tool => 'sh_run',  decision => 'ask',  command => 'git',        # narrowed by command
  args => ['push'], args-any => ['--force', '-f'],
  note => 'force pushes rewrite history', severity => 'danger' }
{ tool => 'web_*',   decision => 'allow', host => '*.raku.org' }  # narrowed by website
=end code

=item C<tool> — an exact tool name, or a prefix glob: a name ending in C<*>
      matches every name that starts with what comes before it. C<*> on its own
      matches everything. A C<*> anywhere else is refused, because a rule that
      silently matches nothing is worse than one that will not load.
=item C<decision> — C<allow>, C<deny> or C<ask>.
=item C<under> — a directory. The rule only has an opinion about calls whose
      location arguments are inside it.
=item C<command> — a program basename, exact or a trailing-C<*> glob (never a
      path separator: it matches the basename, so a C</> could not fire). The
      rule only speaks about calls whose program is this one. C</usr/bin/git>,
      C<git> and C<C:\bin\git.EXE> all match a C<command> of C<git>.
=item C<args> — a list of tokens the call's argv must B<begin> with, in order.
      Needs a C<command>.
=item C<args-any> — a list of tokens, at least one of which must appear
      B<anywhere> in the argv (C<--force> or C<-f>, order no matter). Needs a
      C<command>. Combined with C<args>, both must hold.
=item C<host> — a website. Either an exact host (C<docs.raku.org>) or a
      suffix glob of the one shape C<*.> plus a host (C<*.raku.org>). The rule
      only speaks about calls whose C<url> argument names that site.
=item C<note> — free text saying why the rule exists; a permission prompt shows
      it, so the human is told what they are being asked about.
=item C<severity> — C<danger>, the one value there is. A prompt renders these
      loudly.

Anything else in a rule is refused: C<dir> where C<under> was meant would
otherwise turn a narrow rule into a blanket one, which is exactly the mistake a
permission system must not make quietly. New members only ever refuse more, so
an older engine rejects a rule it does not understand loudly, rather than
under-enforcing it — the safe direction for a permission file to break in.

=head2 Narrowing by command, and failing closed

A rule with a C<command> is measured against the program a call runs and its
argv — the C<command> and C<args> arguments, or whatever C<command-params>
renames them to. The tri-state and the fail-closed asymmetry are the same as
for paths: an B<allow> fires only when the command is one it named; a B<deny> or
B<ask> fires on a match B<or> on anything it cannot read. A call whose argv the
engine cannot see to the end — because a token is not a literal string — is
C<unknown> past that point, so an C<args> prefix that would need to read into
the dark, or an C<args-any> token that is not already visible, keeps a deny or
ask firing and stops an allow.

C<command> and C<under> on one rule are ANDed: both must hold. A rule that
allows C<git> only inside a scratch directory means exactly that.

=head2 Narrowing by host

A rule with a C<host> is measured against the website a call names in its
C<url> argument — the one URL-bearing parameter name there is, the naming a
C<web_search>/C<web_fetch>/C<web_crawl>/C<web_grep> pack follows. Without it,
saying yes once to C<web_fetch> would be saying yes to every site there will
ever be, which is not what a human clicking "always allow" on a documentation
page means.

A C<host> is an exact host, or a suffix glob of exactly one shape: C<*.>
followed by a host. Nothing else glob-ish is accepted — no C<?>, no C<*> in the
middle, no bare C<*>, no empty string — because a pattern that matches nothing
is a permission rule that never fires, and one that matches more than its author
read is worse.

Matching is on the ASCII-lowercased host and on a C<.> boundary, never on the
string:

=begin code :lang<raku>
host => 'docs.raku.org'   # docs.raku.org, DOCS.RAKU.ORG          -- and nothing else
host => '*.raku.org'      # docs.raku.org, a.b.raku.org
                          # NOT raku.org (the glob is a subdomain glob)
                          # NOT evilraku.org (the '.' boundary is the point)
=end code

The host comes out of a deliberately small, strict URL parse: an absolute
C<http> or C<https> URL, its authority taken up to the first C</>, C<?> or
C<#>, brackets stripped from an IPv6 literal, any port dropped. Everything else
— a relative reference, a C<data:> or C<file:> URL, a percent-encoded or
backslash-bearing authority, a value that is not a string — is B<unparseable>,
and so is a URL carrying userinfo: C<https://user@evil.com#@good.com> is a
shape whose host two readers disagree about, and a permission engine may not be
the reader that guesses.

The tri-state and the fail-closed asymmetry are the path predicate's exactly: a
call whose C<url> parses and matches is C<yes>, one that parses and does not is
C<no>, and a call with no C<url> at all or one that cannot be parsed is
C<unknown>. So an B<allow> narrowed by host fires only on a URL it could read
and did recognise, while a B<deny> or B<ask> fires on that B<or> on anything it
could not read. C<host> ANDs with C<under>, C<command> and C<check> as those AND
with each other.

Two things follow, both deliberate:

=item C<url> is B<not> one of the location arguments (see below). A URL is never
      treated as a filesystem path: C<path-under> would read
      C<https://evil.com/> as a relative path with a C<https:> segment and
      answer a question nobody asked;
=item an C<under> narrower on a C<web_*> rule can never fire. Such a call names
      no location arguments, so the path predicate is C<unknown>, and unknown
      fails closed — the allow stays silent, the deny always speaks. Narrow a
      web tool by C<host>, not by C<under>.

=head2 Where paths come from

The location arguments of a call are, by convention, the ones named C<path>,
C<from> and C<to> — the naming the C<MCP::Server::Tool::FileSystem> pack
follows for precisely this reason. C<path-params> overrides the convention per
tool for anything that does not:

=begin code :lang<raku>
path-params => { 'git_*' => ['repo',], 'sql_query' => [] }
=end code

Relative arguments are made absolute against C<roots>, whose keys are
tool-name B<prefixes> (not globs — the longest matching prefix wins, and the
empty string is a catch-all):

=begin code :lang<raku>
roots => { fs => '/srv/docs', '' => '/tmp/agent' }
=end code

A rule's C<under> is absolutized the same way, so a rule may be written
relative to the root it is about.

=head2 Containment is lexical, and tri-state

C<path-under> compares two paths B<segment by segment>, and never touches the
filesystem. Two reasons, both load-bearing:

=item the paths belong to the B<server's> filesystem, which may not be this
      machine's at all — resolving C</srv/docs> here would answer a question
      nobody asked;
=item symlink truth is the server pack's job. C<MCP::Server::Tool::FileSystem>
      resolves every argument inside its sandbox root before touching it; a
      client-side C<.resolve> would be a second, weaker opinion about the same
      question.

Segment-wise, never string-prefix: C</tmp/root2> does not start with
C</tmp/root> in any sense a permission system may act on, however much the two
strings look alike.

The answer has three values, not two. C<unknown> is returned when the question
cannot honestly be answered lexically:

=item a C<..> segment anywhere (the only honest resolution is on the server);
=item a null byte; or a backslash in a path with no Windows volume — on a
      Windows server C<\> is a separator and on a POSIX one it is an ordinary
      character, and guessing wrong either hides an escape or invents one;
=item a Windows path the engine cannot place: drive-relative C<C:x>, a C<\x>
      rooted on whichever drive is current, a C<\\?\> or C<\\.\> device path,
      or a segment Windows would read as some other name — a trailing dot or
      space (C<protected.> B<is> C<protected>), a C<:> (a data stream), a
      device name such as C<NUL> or C<COM1>;
=item a POSIX-rooted path (C</x>) measured against a Windows one: on Windows
      C</x> is the root of whichever drive is current;
=item a path on another Windows volume, for a deny or an ask; and, for any
      rule, a segment of a Windows path that differs from the rule's only by
      being an 8.3 short name (see L<#Windows paths>);
=item an absolute path measured against a relative directory, or the reverse:
      no root was configured, so there is nothing to measure from;
=item an argument that is missing, or is not a string at all.

=head2 Windows paths

A path that starts with a Windows volume is understood as one, whatever the
host: a drive (C<C:\work>, C<C:/work>, the letter in either case) or a UNC
share (C<\\server\share\work>). Inside such a path either separator works, so
C<C:\work\src> and C<C:/work/src> are the same place. Roots and rules may be
written the way Windows writes them:

=begin code :lang<raku>
roots => { fs => 'C:\Users\me\project' },
rules => [ { tool => 'fs_*', decision => 'allow', under => 'C:\Users\me\project\src' } ],
=end code

A relative argument is measured from its root by joining the two, so C<src\x>
under a C<C:\…> root is a Windows path and its backslash separates; under a
POSIX root the same argument stays C<unknown>. The join is spelt with the
root's own separator throughout (C<src/x> under C<C:\work> is
C<C:\work\src\x>), so a path handed back -- a lease, a suggestion -- reads as
the user would type it. An argument that names its own volume (C<D:\x>,
C<\\other\share>) is never joined onto the root.

B<Case.> Deny and ask rules compare segments case-insensitively, so
C<PROTECTED\x> cannot slip past a deny on C<protected> on NTFS. Allow rules
compare exactly, so a differently-cased path is never granted on a
case-sensitive filesystem. Over-matching is the safe direction for the first,
and the unsafe one for the second.

B<Other volumes.> To an allow, a path on another volume is simply not inside
the rule's directory. To a deny or an ask it is C<unknown>, so they fire:
Windows has too many ways for one volume's name to reach another's files for
a string comparison to rule it out — C<\\localhost\C$\work> is C<C:\work>, and
so are C<\\127.0.0.1\c$\work> and the machine's own name; any share, a
C<subst> or mapped drive and a volume mount point alias the same way.

=begin code :lang<raku>
my @rules =
	{ tool => 'fs_*', decision => 'allow', under => 'C:\work' },
	{ tool => 'fs_*', decision => 'deny',  under => 'C:\work\secret' },
;
evaluate(@rules, 'fs_read', { path => '\\\\localhost\C$\work\secret\x' })<decision>;  # deny
evaluate(@rules, 'fs_read', { path => 'D:\x' })<decision>;                            # deny
=end code

B<8.3 short names.> Windows still answers to the short name it gave a long
one: C<C:\work\SECRET~1\x> opens C<C:\work\secret\x>, and which long name a
short one belongs to is written only on the server's disk. So a segment that
differs from the rule's only by being a short name — a base of up to eight
characters holding a C<~> and a letter or digit, and at most a three-letter
extension — is C<unknown> to every rule: a deny on C<C:\work\secret> fires on
it, and an allow on C<C:\work\public> does not. A short name below the rule's
directory changes nothing (C<C:\work\PROGRA~1> is inside C<C:\work> whatever it
stands for), and a name of any other shape (C<notes~2024.md>) is just a name.
Roots and rules may themselves be written with short names — a temporary
directory often is (C<C:\Users\RUNNER~1\AppData\Local\Temp>).

=head2 What C<unknown> does

Fail closed, in both directions:

=item an B<allow> rule with a predicate fires only when the call has location
      arguments and B<every one of them> is C<yes>;
=item a B<deny> or B<ask> rule with a predicate fires on B<any> C<yes> or
      C<unknown> — an argument that cannot be ruled out is not ruled out;
=item every rule is evaluated, and the strongest decision wins:
      B<deny E<gt> ask E<gt> allow>. Order-independence is the point: rule sets
      get serialized, merged and re-ordered, and a permission system whose
      answer depends on which half of the file was read first is not one;
=item B<no rule matched at all is C<ask>>, not allow. A tool nobody wrote a
      rule about is a tool nobody has consented to.

=head1 EXAMPLES

The two-argument case, where fail-closed earns its keep. C<fs_move> declares
both C<from> and C<to>, so a rule that allows moves inside a scratch directory
must be satisfied about both ends:

=begin code :lang<raku>
my @rules = { tool => 'fs_move', decision => 'allow', under => '/srv/scratch' },;

evaluate(@rules, 'fs_move',
	{ from => '/srv/scratch/a', to => '/srv/scratch/b' })<decision>;   # allow
evaluate(@rules, 'fs_move',
	{ from => '/srv/scratch/a', to => '/srv/live/b' })<decision>;      # ask
evaluate(@rules, 'fs_move', { from => '/srv/scratch/a' })<decision>;   # ask
=end code

The suggestion is what a permission prompt offers as its "always allow" — the
deepest directory that contains everything this call touches, never wider than
the tool's configured root:

=begin code :lang<raku>
evaluate((), 'fs_read', { path => 'notes/today.md' },
	roots => { fs => '/srv/docs' })<suggestion>;
# { tool => 'fs_read', under => '/srv/docs/notes' }
=end code

A call that names a website rather than a directory is offered the site it
named, so that "always allow" means this site and not the web:

=begin code :lang<raku>
evaluate((), 'web_fetch', { url => 'https://Docs.Raku.org/lang.html' })<suggestion>;
# { tool => 'web_fetch', host => 'docs.raku.org' }

evaluate((), 'web_fetch', { url => 'not a url' })<suggestion>;
# { tool => 'web_fetch' }   -- nothing honest to scope it to
=end code

And the host predicate, failing closed in both directions:

=begin code :lang<raku>
my @rules =
	{ tool => 'web_fetch', decision => 'allow', host => '*.raku.org' },
	{ tool => 'web_fetch', decision => 'deny',  host => 'evil.com' },
;

evaluate(@rules, 'web_fetch', { url => 'https://docs.raku.org/x' })<decision>;  # allow
evaluate(@rules, 'web_fetch', { url => 'https://raku.org/x' })<decision>;       # ask
evaluate(@rules, 'web_fetch', { url => 'https://evil.com/x' })<decision>;       # deny
evaluate(@rules, 'web_fetch', { url => 'javascript:x' })<decision>;             # deny
=end code

=end pod

use MCP::Client::Exceptions;
use MCP::Client::Policy::Commands;

unit module MCP::Client::Policy::Rules;

# The alphabet a tool name is made of: MCP::Server's own, and the one the
# OpenAI-compatible function-calling APIs accept. A rule naming a tool that
# could never exist is a typo, and a typo in a permission file is a rule that
# never fires.
my $TOOL-ALPHABET = rx/^ <[A..Za..z0..9_-]>* $/;

my constant RULE-KEYS = <tool decision under host command args args-any check note severity>.Set;
my constant DECISIONS = <allow deny ask>.Set;
my constant SEVERITIES = <danger>.Set;

# The location arguments of a tool, unless told otherwise. The FileSystem pack
# names its location parameters exactly this, on purpose.
my constant DEFAULT-PATH-PARAMS = <path from to>;

# The URL arguments of a tool. Deliberately not overridable per tool and
# deliberately not part of DEFAULT-PATH-PARAMS: a web pack names its target
# `url`, and a URL is never a filesystem path -- reading one as a path would
# have `path-under` answering a question nobody asked.
my constant DEFAULT-URL-PARAMS = <url>;

# The program-and-arguments parameters of a tool, unless told otherwise. The
# Shell pack names them exactly this: `command` is the program, `args` its argv
# tail. A command-params entry overrides the pair per tool.
my constant DEFAULT-COMMAND-PARAMS = %( command => 'command', args => 'args' );

# The characters a command pattern is made of. Broader than a tool name --
# executables carry dots and pluses -- but never a path separator: a command
# pattern matches the basename of the program, so a '/' in it could never fire.
my $COMMAND-ALPHABET = rx/^ <[A..Za..z0..9._+-]>* $/;

# The characters a host is made of, on both sides of the comparison: the letters,
# digits, dots and hyphens of a registered name, underscores because internal
# names carry them, and colons because an IPv6 literal arrives here with its
# brackets already stripped. Everything else -- '%', '*', '?', '@', a slash, a
# backslash -- is refused rather than guessed at, in a rule and in a URL alike.
my $HOST-ALPHABET = rx/^ <[A..Za..z0..9._:-]>+ $/;

# === Rules ===

#| Check one rule and return a normalised plain-data copy of it, or die with an
#| C<X::MCP::Client> naming what is wrong with it. C<what> appears in the
#| message, so a bad session grant does not report itself as a bad rule.
our sub validate-rule($rule, Str:D :$what = 'policy rule' --> Hash:D) is export {
	die X::MCP::Client.new(
		detail => "a $what must be an object with a tool and a decision, not "
			~ ($rule.defined ?? 'a ' ~ $rule.^name !! 'an undefined ' ~ $rule.^name),
	) unless $rule ~~ Associative;

	my %given = $rule.Hash;

	my @unknown = %given.keys.grep({ !RULE-KEYS{$_} }).sort;
	die X::MCP::Client.new(
		detail => "unknown member(s) in a $what: '{@unknown.join(q{', '})}'; a $what is made of "
			~ 'tool, decision, and optionally under, host, command, args, args-any, check, note '
				~ 'and severity',
	) if @unknown;

	my $tool = %given<tool>;
	die X::MCP::Client.new(
		detail => "a $what must name a tool, as an exact name or a trailing-'*' prefix glob",
	) unless $tool ~~ Str:D && $tool.chars;

	my $glob = $tool.ends-with('*');
	my $stem = $glob ?? $tool.substr(0, *-1) !! $tool;
	die X::MCP::Client.new(
		detail => "invalid tool pattern '$tool' in a $what: a pattern is a tool name made of "
			~ "letters, digits, underscores and hyphens, optionally ending in '*'",
	) unless $stem ~~ $TOOL-ALPHABET && ($glob || $stem.chars);

	my $decision = %given<decision>;
	die X::MCP::Client.new(
		detail => "invalid decision '{$decision // 'none'}' in a $what for '$tool': "
			~ "a decision is one of 'allow', 'deny' or 'ask'",
	) unless $decision ~~ Str:D && DECISIONS{$decision};

	my %rule = tool => $tool.Str, decision => $decision.Str;

	if %given<under>:exists {
		my $under = %given<under>;
		my %parsed = parse-path($under);
		die X::MCP::Client.new(
			detail => "invalid under '{$under.defined ?? $under.Str !! 'undefined'}' in a $what "
				~ "for '$tool': {path-complaint(%parsed<reason>)}",
		) unless %parsed<ok>;
		%rule<under> = $under.Str;
	}

	if %given<host>:exists {
		my $host = %given<host>;
		die X::MCP::Client.new(
			detail => "invalid host '{$host.defined ?? $host.Str !! 'undefined'}' in a $what "
				~ "for '$tool': a host is a website, as an exact host name or a '*.' suffix glob "
				~ "of one ('*.example.com'), with no other wildcard, scheme, port or path",
		) unless $host ~~ Str:D && host-pattern-ok($host);
		%rule<host> = $host.Str;
	}

	if %given<command>:exists {
		my $command = %given<command>;
		die X::MCP::Client.new(
			detail => "invalid command '{$command.defined ?? $command.Str !! 'undefined'}' in a $what "
				~ "for '$tool': a command is a program basename, as an exact name or a trailing-'*' "
				~ "prefix glob, with no path separator",
		) unless $command ~~ Str:D && $command.chars && command-pattern-ok($command);
		%rule<command> = $command.Str;
	}

	for <args args-any> -> $key {
		next unless %given{$key}:exists;
		die X::MCP::Client.new(
			detail => "a $what for '$tool' has '$key' without a command: '$key' narrows a command "
				~ 'match, so it only means something alongside a command pattern',
		) unless %given<command>:exists;

		my $tokens = %given{$key};
		die X::MCP::Client.new(
			detail => "invalid $key in a $what for '$tool': $key is a list of argument tokens, "
				~ 'each a non-empty string',
		) unless $tokens ~~ Positional
			&& !$tokens.list.grep({ !($_ ~~ Str:D) || !$_.chars });
		# Eager: a lazy map here would be a view onto the caller's own list,
		# so the rule could change after it was validated, and the first
		# thread to read it would be the one to fill it in.
		%rule{$key} = $tokens.list.map(*.Str).eager.List;
	}

	if %given<check>:exists {
		my $check = %given<check>;
		die X::MCP::Client.new(
			detail => "invalid check in a $what for '$tool': a check names a semantic predicate "
				~ 'the policy supplies, as a non-empty string',
		) unless $check ~~ Str:D && $check.chars;
		%rule<check> = $check.Str;
	}

	if %given<note>:exists {
		my $note = %given<note>;
		die X::MCP::Client.new(
			detail => "invalid note in a $what for '$tool': a note is a string explaining why the "
				~ 'rule exists',
		) unless $note ~~ Str:D;
		%rule<note> = $note.Str;
	}

	if %given<severity>:exists {
		my $severity = %given<severity>;
		die X::MCP::Client.new(
			detail => "invalid severity '{$severity // 'none'}' in a $what for '$tool': the only "
				~ "severity is 'danger'",
		) unless $severity ~~ Str:D && SEVERITIES{$severity};
		%rule<severity> = $severity.Str;
	}

	%rule;
}

#| Whether a command pattern is well-formed: a program basename made of the
#| command alphabet, optionally ending in a single C<*>, and never containing a
#| path separator (it matches a basename, so a separator could not fire).
our sub command-pattern-ok(Str:D $pattern --> Bool:D) is export {
	return False if $pattern.contains('/') || $pattern.contains('\\');
	my $glob = $pattern.ends-with('*');
	my $stem = $glob ?? $pattern.substr(0, *-1) !! $pattern;
	so $stem ~~ $COMMAND-ALPHABET && ($glob || $stem.chars);
}

#| Whether a host pattern is well-formed: a host made of the host alphabet, or
#| C<*.> followed by one. The C<*.> prefix is the B<only> wildcard there is — a
#| bare C<*>, a C<*> in the middle, a C<?> and an empty string are all refused,
#| because a pattern that could never fire is worse in a permission file than one
#| that will not load. A leading or trailing dot is refused too: C<.example.com>
#| is C<*.example.com> written by someone who meant the glob, and C<example.com.>
#| is the same site spelled a second way, which a rule may not be.
our sub host-pattern-ok(Str:D $pattern --> Bool:D) is export {
	my $glob = $pattern.starts-with('*.');
	my $stem = $glob ?? $pattern.substr(2) !! $pattern;
	return False unless $stem ~~ $HOST-ALPHABET;
	return False if $stem.starts-with('.') || $stem.ends-with('.');
	# A colon is an IPv6 literal's, and nothing else's: `raku.org:443` is a rule
	# about a socket, and the parse drops ports long before matching, so such a
	# rule could never fire -- which is the one thing this schema exists to catch.
	return False if $stem.contains(':') && !ipv6-literal-ok($stem);
	so $stem ~~ /<[A..Za..z0..9]>/;
}

# Whether a string is an IPv6 literal as this engine will read one: hex digits,
# colons and the dots of an IPv4-mapped tail, with at least the two colons every
# IPv6 address has. Textual, not numeric -- `::1` and `0:0:0:0:0:0:0:1` are the
# same address and not the same host pattern, which is the price of never
# pretending to be a resolver.
my sub ipv6-literal-ok(Str:D $literal --> Bool:D) {
	return False unless $literal ~~ /^ <[0..9A..Fa..f:.]>+ $/;
	$literal.comb.grep(* eq ':').elems >= 2;
}

#| Whether a host pattern matches a host: an exact pattern matches only itself,
#| and a C<*.> pattern matches every host below it — on a C<.> boundary, so
#| C<*.raku.org> covers C<docs.raku.org> but neither C<raku.org> (which is the
#| site itself, not a site under it) nor C<evilraku.org> (which merely ends in
#| the same letters). Case-insensitive: hosts are, and the alphabet is ASCII, so
#| C<.lc> is the whole of the folding needed.
our sub match-host($pattern, $host --> Bool:D) is export {
	return False unless $pattern ~~ Str:D && $host ~~ Str:D;
	my $p = $pattern.lc;
	my $h = $host.lc;

	if $p.starts-with('*.') {
		my $stem = $p.substr(2);
		return False unless $stem.chars;
		return $h.ends-with('.' ~ $stem);
	}

	$p eq $h;
}

#| The host a URL names, ASCII-lowercased, or an B<undefined> C<Str> when the
#| string is not one this engine will claim to understand. Deliberately minimal
#| and deliberately strict, because every "clever" reading of a malformed URL is
#| a disagreement waiting to happen between this engine and whatever fetches the
#| page. The scheme must be C<http> or C<https>, spelled out with C<://>: a
#| relative reference has no host to speak of, and a C<data:> or C<file:> URL is
#| not a website. The authority is everything up to the first C</>, C<?> or
#| C<#>. An IPv6 literal loses its brackets and keeps its colons, and a port is
#| dropped — but must be digits if it is there at all. A trailing root dot is
#| dropped too, so C<evil.com.> cannot walk past a rule about C<evil.com>.
#|
#| C<userinfo> is refused outright rather than skipped past:
#| C<https://docs.raku.org@evil.com/> and C<https://user@evil.com#@good.com> are
#| exactly the shapes a reader gets wrong, and the safe answer to a question
#| with two answers is "I cannot read this". So is anything left holding a
#| character outside the host alphabet — a percent-encoding, a backslash, a
#| space — which is unreadable, never repaired.
our sub url-host($value --> Str) is export {
	return Str unless $value ~~ Str:D;
	my $raw = $value.Str;
	return Str unless $raw.chars;
	# Control characters and whitespace are stripped or rejected differently by
	# every URL parser there is; this one refuses the string outright.
	return Str if $raw.comb.grep({ .ord <= 0x20 || .ord == 0x7F });

	my $lc = $raw.lc;
	my $rest;
	if    $lc.starts-with('http://')  { $rest = $raw.substr(7) }
	elsif $lc.starts-with('https://') { $rest = $raw.substr(8) }
	else                              { return Str }

	# The authority ends where the path, query or fragment begins -- whichever
	# comes first, so that a '#' before the first '/' cannot smuggle a second
	# host into what looks like a path.
	my $end = $rest.chars;
	for ('/', '?', '#') -> $mark {
		my $at = $rest.index($mark);
		$end = $at if $at.defined && $at < $end;
	}
	my $authority = $rest.substr(0, $end);
	return Str unless $authority.chars;
	return Str if $authority.contains('@');

	my $host;
	if $authority.starts-with('[') {
		my $close = $authority.index(']');
		return Str unless $close.defined;
		$host = $authority.substr(1, $close - 1);
		my $tail = $authority.substr($close + 1);
		return Str unless $tail eq '' || port-ok($tail);
		# Brackets mean an IPv6 literal, so what is inside them has to be one --
		# a bracketed registered name is a shape no client agrees about.
		return Str unless ipv6-literal-ok($host);
	}
	else {
		return Str if $authority.contains(']');
		my @parts = $authority.split(':');
		# One colon at most: a bare IPv6 literal (which must have been bracketed)
		# is not something to guess the port boundary of.
		return Str if @parts.elems > 2;
		$host = @parts[0];
		return Str if @parts.elems == 2 && !port-ok(':' ~ @parts[1]);
	}

	# The root dot is the same site said twice; drop exactly one, and refuse the
	# rest rather than looping a normalisation nobody asked for.
	$host = $host.chop if $host.ends-with('.');
	return Str unless $host.chars && $host ~~ $HOST-ALPHABET;
	return Str if $host.starts-with('.') || $host.ends-with('.');

	$host.lc;
}

# A port, as it appears after the host: a colon and then digits, or a colon and
# nothing (which RFC 3986 permits and every client reads as "the default").
my sub port-ok(Str:D $tail --> Bool:D) {
	return False unless $tail.starts-with(':');
	so $tail.substr(1) ~~ /^ <[0..9]>* $/;
}

#| Check a whole rule list and return normalised plain-data copies, in order.
our sub validate-rules($rules, Str:D :$what = 'policy rule' --> List:D) is export {
	return ().List without $rules;
	die X::MCP::Client.new(
		detail => "the {$what}s must be a list of rule objects, not a {$rules.^name}",
	) unless $rules ~~ Positional;

	$rules.list.map({ validate-rule($_, :$what) }).List;
}

#| Check the C<roots> table — tool-name prefix to directory — and return a
#| normalised copy.
our sub validate-roots($roots --> Hash:D) is export {
	return {} without $roots;
	die X::MCP::Client.new(
		detail => "the policy roots must be an object of tool-name prefix to directory, not a {$roots.^name}",
	) unless $roots ~~ Associative;

	my %out;
	for $roots.Hash.kv -> $prefix, $dir {
		die X::MCP::Client.new(
			detail => "invalid root directory for the prefix '$prefix': "
				~ path-complaint(parse-path($dir)<reason>),
		) unless parse-path($dir)<ok>;
		%out{$prefix} = $dir.Str;
	}

	%out;
}

#| Check the C<path-params> table — tool pattern to the names of that tool's
#| location arguments — and return a normalised copy.
our sub validate-path-params($params --> Hash:D) is export {
	return {} without $params;
	die X::MCP::Client.new(
		detail => 'the policy path-params must be an object of tool pattern to argument names, '
			~ "not a {$params.^name}",
	) unless $params ~~ Associative;

	my %out;
	for $params.Hash.kv -> $pattern, $names {
		# Validated as a rule's tool pattern is, so the two tables agree about
		# what a pattern is.
		validate-rule({ tool => $pattern, decision => 'ask' }, what => 'path-params pattern');

		# A bare string is the one-argument case spelled the obvious way. An
		# empty list is legitimate and means "this tool names no locations", so
		# emptiness cannot be the failure signal -- hence the undefined one.
		my $named = do given $names {
			when Str:D      { ($names,).List }
			when Positional { $names.list.List }
			default         { List }
		};

		die X::MCP::Client.new(
			detail => "invalid path-params for '$pattern': the location arguments of a tool are "
				~ 'a list of argument names (or a single name), and may be an empty list',
		) without $named;

		die X::MCP::Client.new(
			detail => "invalid path-params for '$pattern': every location argument name must be "
				~ 'a non-empty string',
		) if $named.grep({ !($_ ~~ Str:D) || !$_.chars });

		# Eager: the table is read by every concurrent decision without a
		# lock, and a lazy List would be filled in by whichever got there first.
		%out{$pattern} = $named.map(*.Str).eager.List;
	}

	%out;
}

#| Check the C<command-params> table — tool pattern to the names of that tool's
#| program and argv parameters — and return a normalised copy. A value is an
#| object with an optional C<command> and an optional C<args>, each naming a
#| parameter; whatever it omits falls back to the C<command>/C<args> convention.
our sub validate-command-params($params --> Hash:D) is export {
	return {} without $params;
	die X::MCP::Client.new(
		detail => 'the policy command-params must be an object of tool pattern to parameter names, '
			~ "not a {$params.^name}",
	) unless $params ~~ Associative;

	my %out;
	for $params.Hash.kv -> $pattern, $spec {
		# Validated as a rule's tool pattern is, so the tables agree about
		# what a pattern is.
		validate-rule({ tool => $pattern, decision => 'ask' }, what => 'command-params pattern');

		die X::MCP::Client.new(
			detail => "invalid command-params for '$pattern': the program and argv parameters of a "
				~ "tool are named by an object with an optional command and an optional args",
		) unless $spec ~~ Associative;

		my %given = $spec.Hash;
		my @unknown = %given.keys.grep({ $_ ne 'command' && $_ ne 'args' }).sort;
		die X::MCP::Client.new(
			detail => "invalid command-params for '$pattern': unknown member(s) "
				~ "'{@unknown.join(q{', '})}'; only command and args name a parameter",
		) if @unknown;

		my %names;
		for <command args> -> $slot {
			next unless %given{$slot}:exists;
			die X::MCP::Client.new(
				detail => "invalid command-params for '$pattern': $slot must name a parameter, "
					~ 'as a non-empty string',
			) unless %given{$slot} ~~ Str:D && %given{$slot}.chars;
			%names{$slot} = %given{$slot}.Str;
		}
		%out{$pattern} = %names;
	}

	%out;
}

#| Whether a tool-name pattern — an exact name, or a name ending in C<*> —
#| matches a tool name.
our sub match-tool($pattern, $name --> Bool:D) is export {
	return False unless $pattern ~~ Str:D && $name ~~ Str:D;
	return $name.starts-with($pattern.substr(0, *-1)) if $pattern.ends-with('*');
	$pattern eq $name;
}

#| Whether a command pattern matches a program basename. Same trailing-C<*>
#| glob as tool matching, but over the already-normalised basename. With
#| C<:fold> the comparison ignores case — used for deny/ask, where over-matching
#| a case variant on a case-insensitive host is safe; allow stays case-exact so
#| it never grants a differently-cased binary on a case-sensitive one.
our sub match-command($pattern, $basename, Bool :$fold --> Bool:D) is export {
	return False unless $pattern ~~ Str:D && $basename ~~ Str:D;
	my ($p, $b) = $fold ?? ($pattern.fc, $basename.fc) !! ($pattern, $basename);
	return $b.starts-with($p.substr(0, *-1)) if $p.ends-with('*');
	$p eq $b;
}

#| Whether C<$path> is inside C<$dir>: C<'yes'>, C<'no'>, or C<'unknown'> when
#| the question cannot be answered by looking at the two strings. Purely
#| lexical, segment by segment; a directory is inside itself.
#|
#| A POSIX-rooted path measured against a Windows one is C<unknown>: on
#| Windows, C</x> is the root of whichever drive is current.
#|
#| C<:fold> is the fail-closed comparison, for the callers to whom
#| over-matching is the safe direction: deny and ask rules, and lease
#| collisions. It compares the segments case-insensitively, so C<PROTECTED/x>
#| cannot slip past a deny on C<protected> on a case-insensitive filesystem; and
#| it answers C<unknown>, never C<no>, for paths on two different Windows
#| volumes, because C<\\localhost\C$\x>, a share, a C<subst> or mapped drive
#| and a mount point all reach one volume's files by another's name. Without
#| C<:fold> — an allow — a differently-cased path is not inside, so it is
#| never granted on a case-sensitive filesystem, and two volumes are C<no>.
#|
#| On a Windows path a segment that differs from its counterpart only by
#| being an 8.3 short name (C<SECRET~1> against C<secret>) is C<unknown>
#| either way: Windows opens the long name the short one was given to, which
#| only the server's disk knows. See C<windows-short-name>.
our sub path-under($dir, $path, Bool :$fold --> Str:D) is export {
	my %d = parse-path($dir);
	my %p = parse-path($path);
	return 'unknown' unless %d<ok> && %p<ok>;
	return 'unknown' unless %d<absolute> eqv %p<absolute>;
	if %d<volume> ne %p<volume> {
		# A POSIX-rooted path against a Windows one is the current drive's,
		# whichever that is. Two different Windows volumes are two places as
		# far as an allow is concerned, but not provably so: an admin share
		# (\\localhost\C$, \\127.0.0.1\c$, the machine's own name), any share,
		# a subst or mapped drive and a volume mount point all reach one
		# volume's files through another's name. So a deny, an ask or a lease
		# collision -- the :fold callers, for which over-matching is the safe
		# direction -- cannot be told 'no'.
		return 'unknown' if $fold || !(%d<volume>.chars && %p<volume>.chars);
		return 'no';
	}

	my @dir = %d<segments>.list;
	my @in = %p<segments>.list;
	return 'no' if @in.elems < @dir.elems;

	# Segment by segment. On a Windows volume two different names are still
	# not provably two places when either is an 8.3 short name: SECRET~1 is
	# whichever long name in that directory Windows gave that short name to,
	# and only the server's disk knows which. Such a pair is 'unknown' -- but
	# a pair of names that definitely differ anywhere makes the answer 'no'.
	my Bool $windows = ?%d<volume>.chars;
	my Bool $unsure = False;
	for @dir.kv -> $i, $want {
		my $have = @in[$i];
		next if $fold ?? $have.fc eq $want.fc !! $have eq $want;
		return 'no' unless $windows && (windows-short-name($have) || windows-short-name($want));
		$unsure = True;
	}

	$unsure ?? 'unknown' !! 'yes';
}

#| Whether a path segment could be an 8.3 short name — C<PROGRA~1>,
#| C<SECRET~1.TXT>, a Samba server's mangled C<SECRE~A1> — which Windows
#| resolves to whichever long name in that directory it was given to. The
#| shape: a base of one to eight characters holding a C<~> followed by a letter
#| or digit, and an optional extension of one to three. A name outside that
#| shape cannot be a short name, so C<notes~2024.md> is just a name. Used by
#| C<path-under> on Windows paths, and by the danger floor; not exported.
our sub windows-short-name(Str:D $segment --> Bool:D) {
	return False unless $segment ~~ / ^ $<base>=[<-[.]> ** 1..8] [ '.' <-[.]> ** 1..3 ]? $ /;
	so ~$<base> ~~ / '~' <[A..Za..z0..9]> /;
}

#| Decide what to do about one call. Returns
#| C<< { decision, reason, rule, paths, suggestion } >>: the decision, why it
#| was reached (C<'rule'>, C<'no-match'> or C<'unevaluable-path'>), the
#| most-specific rule behind it (an undefined C<Hash> when none matched), the
#| call's location arguments as the engine saw them, and the rule a permission
#| prompt should offer as its "always" answer.
#|
#| C<$args> is the parsed arguments of the call. Anything that is not an
#| object — including the sentinel a caller passes for arguments that would not
#| parse — makes every path predicate C<unknown>.
#|
#| A rule may also narrow by C<command>/C<args>/C<args-any>, matched against the
#| call's program and argv (the C<command>/C<args> parameters, or whatever
#| C<command-params> renames them to), or by C<host>, matched against the site
#| the call's C<url> argument names. A rule bearing several predicates fires only
#| when B<all> of them hold — they are ANDed, each tri-state and each failing
#| closed exactly as the path predicate does.
our sub evaluate(
	@rules, $tool, $args, :%roots, :%path-params, :%command-params, :%checks
	--> Hash:D
) is export {
	my $name = $tool ~~ Str:D ?? $tool !! '';
	my $root = root-for($name, %roots);
	my @located = located-args($name, $args, %path-params, $root);
	my @paths = @located.map({ $_<path> }).grep({ $_ ~~ Str:D }).List;
	my @commands = effective-commands($name, $args, %command-params);
	# What a command or check predicate does when there are no effective
	# commands — and that is two situations, not one.
	#
	# A call that shows us its arguments, and whose arguments name neither the
	# program slot nor the argv slot, gives such a predicate nothing to speak
	# about: `sh_poll` names a job handle and can run nothing, so "deny sh_*
	# where the command writes config" is not a question about it. That is
	# 'no' — the rule does not match. See call-omits-command.
	#
	# Everything else stays 'unknown' and keeps failing closed — unreadable
	# arguments, an empty argument object, and a call carrying either slot
	# unreadably — because in each of those a command really might be hiding.
	#
	# Conflating the two made every danger-floor rule narrowed by command or
	# check fire on sh_poll, sh_output and sh_kill. The floor's
	# self-modification rule is a DENY, and deny outranks ask, so the human was
	# never even asked: a background job could be started and then never read.
	my @no-command = call-omits-command($name, $args, %command-params)
		?? ('no',) !! ('unknown',);
	my @urls = url-args($args);

	my %won;                # decision => { rule, by-unknown }
	my Bool $saw-unknown = False;

	for @rules.list -> $raw {
		next unless $raw ~~ Associative;
		my %rule = $raw.Hash;
		next unless DECISIONS{%rule<decision> // ''};
		next unless match-tool(%rule<tool>, $name);

		my $allow = %rule<decision> eq 'allow';
		my @dims;   # one { fires, by-unknown, saw-unknown } per present predicate

		if %rule<under>:exists {
			# The rule's directory is measured from the same root the call's
			# arguments are, so a rule may be written relative to the sandbox it
			# is about.
			my $under = absolutize(%rule<under>, $root);

			# No location arguments at all is not "nothing to object to": it is a
			# predicate that could not be evaluated, and those go the safe way.
			# Deny and ask compare case-insensitively, allow exactly: see
			# path-under's :fold.
			my @verdicts = @located
				?? @located.map({ path-under($under, $_<path>, :fold(!$allow)) }).List
				!! ('unknown',);
			@dims.push: dimension-verdict($allow, @verdicts);
		}

		if %rule<host>:exists {
			# The site the call names, if the engine could read one. A call with no
			# url at all is unevaluable rather than exempt, exactly as a call with
			# no location arguments is -- which is also why an `under` on a web
			# tool can only ever fail closed, never fire.
			my @verdicts = @urls
				?? @urls.map({ host-verdict(%rule<host>, $_<host>) }).List
				!! ('unknown',);
			@dims.push: dimension-verdict($allow, @verdicts);
		}

		if %rule<command>:exists {
			# Every effective command must clear the predicate for an allow to
			# fire; any one that matches or cannot be ruled out fires a deny/ask.
			# With no effective commands at all, @no-command decides — see it.
			my @verdicts = @commands
				?? @commands.map({ command-verdict(%rule, $_) }).List
				!! @no-command;
			@dims.push: dimension-verdict($allow, @verdicts);
		}

		if %rule<check>:exists {
			# A named semantic predicate the policy supplied (the danger floor's
			# target analysis lives here). Over the same effective commands, so
			# it ANDs with command/under exactly as they AND with each other. An
			# unknown check name is unevaluable, and unevaluable fails closed.
			my @verdicts = @commands
				?? @commands.map({ run-check(%checks, %rule<check>, $_) }).List
				!! @no-command;
			@dims.push: dimension-verdict($allow, @verdicts);
		}

		$saw-unknown = True if @dims.grep(*<saw-unknown>);

		# A bare rule (no predicate) always fires; a predicated rule fires only
		# when every one of its predicates does. by-unknown surfaces when the
		# rule leaned on an argument it could not evaluate.
		my $fires = @dims ?? !@dims.grep({ !$_<fires> }) !! True;
		next unless $fires;
		my $by-unknown = so @dims.grep(*<by-unknown>);

		my $decision = %rule<decision>;
		%won{$decision} = %( rule => %rule, by-unknown => $by-unknown )
			if !(%won{$decision}:exists) || more-specific(%rule, %won{$decision}<rule>);
	}

	my $decision = 'ask';
	my $reason = $saw-unknown ?? 'unevaluable-path' !! 'no-match';
	my $winner = Hash;

	for <deny ask allow> -> $candidate {
		next unless %won{$candidate}:exists;
		$decision = $candidate;
		$winner = %won{$candidate}<rule>;
		$reason = %won{$candidate}<by-unknown> ?? 'unevaluable-path' !! 'rule';
		last;
	}

	{
		decision   => $decision,
		reason     => $reason,
		rule       => $winner,
		paths      => @paths.List,
		suggestion => suggest($name, @paths, $root, host => suggestible-host(@urls)),
	};
}

#| The rule a permission prompt offers as its "always allow" / "always deny":
#| the tool, plus the deepest directory containing every path the call names,
#| clamped to the tool's configured root. C<under> is left out entirely when no
#| directory can be named lexically.
#|
#| A call that named no directory but B<did> name a readable website is scoped by
#| C<host> instead, so that the "always allow" a human is offered for a fetch is
#| this site rather than the whole web. Never both: a call with paths is a
#| filesystem call, and the directory is the narrower answer. A C<:host> that is
#| undefined — no C<url>, or one that would not parse — leaves the suggestion
#| bare, which is the honest fallback and the old behaviour exactly.
our sub suggest(Str:D $tool, @paths, $root, Str :$host --> Hash:D) is export {
	my %suggestion = tool => $tool;
	my %scoped = $host.defined && $host.chars ?? %( tool => $tool, host => $host ) !! %suggestion;

	my @parsed = @paths.map({ parse-path($_) }).grep({ $_<ok> });
	return %scoped unless @parsed;
	return %scoped unless @parsed.map({ $_<absolute> }).unique.elems == 1;
	# One volume too: nothing contains both C:/x and D:/y.
	return %scoped unless @parsed.map({ $_<volume> }).unique.elems == 1;

	# The containing directory of each path, not the path itself: the answer to
	# "may I read /srv/docs/x?" that a human means is nearly always "yes, that
	# directory". Whether a path names a file or a directory cannot be known
	# without touching the server's disk, which this engine never does.
	my @dirs = @parsed.map(-> %p {
		my @segments = %p<segments>.list;
		@segments.elems ?? @segments.head(@segments.elems - 1).List !! ().List;
	});
	my @common = common-prefix(@dirs);

	my $absolute = @parsed[0]<absolute>;
	my $dir = render-path(@parsed[0]<volume>, $absolute, @common);
	return %scoped unless $dir.chars;

	# Never offer to grant more than the tool's own root: a call for /x.txt
	# under a root of /srv would otherwise suggest '/'. Only ever a narrowing,
	# though -- a call whose paths are somewhere else entirely (/etc) gets the
	# directory it really named, because a suggestion that does not contain the
	# call it was suggested for would be a lie.
	$dir = $root if $root ~~ Str:D
		&& path-under($root, $dir) ne 'yes'
		&& !@paths.grep({ path-under($root, $_) ne 'yes' });

	%suggestion<under> = $dir;
	%suggestion;
}

# === Paths ===

# The names NTFS gives to devices: a segment naming one -- bare or with any
# extension, so `nul.txt` too -- opens the device, not a file. COM and LPT
# take any digit, the superscripts ¹ ² ³ included (Windows reads those as 1, 2
# and 3).
my constant WINDOWS-DEVICES = set flat <CON PRN AUX NUL CONIN$ CONOUT$>,
	(|(0..9), '¹', '²', '³').map({ "COM$_", "LPT$_" });

# A segment that NTFS would read as some other name, or not as a name at all:
# a trailing dot or space (dropped, so `protected.` IS `protected`), a colon
# (`x:stream` is a stream of `x`), a reserved device name, or a character
# Windows refuses in a name. Lexically unanswerable, so a path holding one is
# `unknown` -- and only on a Windows path: on POSIX every one of these is an
# ordinary name.
my sub windows-hazard(Str:D $segment --> Bool:D) {
	return True if $segment.ends-with('.') || $segment.ends-with(' ');
	return True if $segment ~~ / <[ : < > " | ? * ]> | <[ \x[00] .. \x[1F] ]> /;
	$segment.split('.', 2).head.trim-trailing.uc (elem) WINDOWS-DEVICES;
}

# One path, taken apart lexically. `ok` is False whenever the string cannot be
# reasoned about at all, with `reason` saying which way it was hopeless -- the
# tri-state's `unknown` and validate-rule's error message both come from here,
# so the two can never disagree about what a usable path is.
#
# A path with a Windows volume -- `C:\x` or `C:/x` (a drive, normalised to an
# upper-case letter), or `\\host\share\x` (a UNC share, case-folded) -- is
# recognised from the string alone and may use either separator; its
# `volume` is part of what it names. Every other path is POSIX-shaped: `/`
# separates and a backslash is an ordinary character, which on a Windows
# server would be a separator, so it is refused rather than guessed at. A
# relative argument measured from a Windows root becomes a Windows path when
# absolutize joins the two, so `src\x` under `C:\work` is understood.
my sub parse-path($value --> Hash:D) {
	return %( ok => False, reason => 'not-a-string' ) unless $value ~~ Str:D;

	my $raw = $value.Str;
	return %( ok => False, reason => 'empty' ) unless $raw.chars;
	return %( ok => False, reason => 'null-byte' ) if $raw.contains("\0");

	my Str $volume = '';
	my Str $rest = $raw;
	# \\?\ and \\.\ (or with either slash) skip Windows' own normalisation and
	# reach devices and raw volumes; no lexical answer about them is honest.
	if $raw ~~ / ^ <[\\/]> <[\\/]> <[?.]> [ <[\\/]> | $ ] / {
		return %( ok => False, reason => 'device-path' );
	}
	elsif $raw ~~ / ^ '\\\\' $<host>=[<-[\\/]>+] <[\\/]> $<share>=[<-[\\/]>+] [ <[\\/]> $<tail>=[.*] ]? $ / {
		$volume = '\\\\' ~ ~$<host>.fc ~ '\\' ~ ~$<share>.fc;
		$rest = ~($<tail> // '');
	}
	elsif $raw ~~ / ^ $<drive>=[<[A..Za..z]>] ':' <[\\/]> $<tail>=[.*] $ / {
		$volume = $<drive>.uc ~ ':';
		$rest = ~$<tail>;
	}
	elsif $raw ~~ / ^ <[A..Za..z]> ':' / {
		# `C:x` is relative to drive C's current directory, which only the
		# server process knows.
		return %( ok => False, reason => 'drive-relative' );
	}
	elsif $raw.starts-with('\\') {
		# `\x` is the root of whichever drive is current; `\\host` with no
		# share is not a location at all.
		return %( ok => False, reason => 'rooted' );
	}

	my Bool $windows = ?$volume.chars;
	return %( ok => False, reason => 'backslash' ) if !$windows && $raw.contains('\\');

	# Empty segments (a doubled or trailing slash) and '.' carry no meaning;
	# '..' carries too much of it to guess at.
	my @segments = $rest.split($windows ?? / <[\\/]> / !! '/').grep({ $_ ne '' && $_ ne '.' });
	return %( ok => False, reason => 'traversal' ) if @segments.grep(* eq '..');
	return %( ok => False, reason => 'windows-name' )
		if $windows && @segments.first({ windows-hazard($_) }).defined;

	%(
		ok       => True,
		reason   => '',
		volume   => $volume,
		absolute => $windows || $raw.starts-with('/'),
		segments => @segments.List,
	);
}

# A path back in canonical form: `/` between segments, after the volume when
# there is one (`C:/x`, `\\host\share/x`), so that it parses back to itself.
my sub render-path(Str:D $volume, Bool() $absolute, @segments --> Str:D) {
	$volume.chars
		?? $volume ~ '/' ~ @segments.join('/')
		!! ($absolute ?? '/' !! '') ~ @segments.join('/');
}

my sub path-complaint(Str:D $reason --> Str:D) {
	given $reason {
		when 'not-a-string'   { 'a directory must be a string' }
		when 'empty'          { 'a directory cannot be empty' }
		when 'null-byte'      { 'a path may not contain a null byte' }
		when 'backslash'      { "a path without a Windows volume may not contain a backslash: "
			~ "write it with '/', or give the whole Windows path (C:\\..., \\\\server\\share\\...)" }
		when 'traversal'      { "a path may not contain a '..' segment, which only the server could resolve" }
		when 'drive-relative' { "'C:x' is relative to a drive's current directory, which only the "
			~ "server knows: write C:\\x" }
		when 'rooted'         { "a path starting with a single backslash is relative to the current "
			~ "drive, which only the server knows: give the drive (C:\\x)" }
		when 'device-path'    { "\\\\?\\ and \\\\.\\ paths reach devices and skip Windows' path "
			~ 'normalisation: give the plain path' }
		when 'windows-name'   { 'a Windows path segment may not end in a dot or a space, contain '
			~ ':, <, >, ", |, ? or *, or be a device name (CON, NUL, COM1, ...): Windows would '
			~ 'read it as some other name' }
		default               { 'it is not a usable path' }
	}
}

#| The root a tool's relative arguments are measured from: the longest matching
#| tool-name prefix, so C<fs> and C<fs_ext> may both have one and C<''> is a
#| catch-all. Prefixes rather than globs, and deliberately: a root is about
#| where a whole family of tools lives, not about matching names. An undefined
#| C<Str> when no prefix matches — arguments then stand as the call wrote them.
#|
#| Exported so that a layer stacked B<beside> the policy —
#| L<MCP::Client::Leases|lib/MCP/Client/Leases.rakumod>, say — locates a call's
#| paths by running the same three functions over the same two tables, rather
#| than by reimplementing the convention and drifting from it.
our sub root-for(Str:D $name, %roots --> Str) is export {
	my $best-prefix = Str;
	my $best = Str;

	for %roots.kv -> $prefix, $dir {
		next unless $name.starts-with($prefix);
		next if $best-prefix.defined && $prefix.chars <= $best-prefix.chars;
		$best-prefix = $prefix;
		$best = $dir;
	}

	$best;
}

#| The names of a tool's location arguments: the C<path>/C<from>/C<to>
#| convention, unless a C<path-params> entry overrides it. The most specific
#| matching pattern wins, by the same ordering rules that pick between two
#| matching rules. An explicit empty list means "this tool names no locations",
#| which is a real answer and not a fallback to the convention.
our sub path-params-for(Str:D $name, %path-params --> List:D) is export {
	my $best-pattern = Str;
	my @best;

	for %path-params.kv -> $pattern, $names {
		next unless match-tool($pattern, $name);
		next if $best-pattern.defined
			&& !more-specific({ tool => $pattern, decision => 'ask' },
				{ tool => $best-pattern, decision => 'ask' });
		$best-pattern = $pattern;
		@best = $names ~~ Str:D ?? ($names,) !! ($names ~~ Positional ?? $names.list !! ());
	}

	$best-pattern.defined ?? @best.List !! DEFAULT-PATH-PARAMS.List;
}

#| Every location argument of a call, in the order the tool's parameters are
#| declared in: one C<< { param, value, path } >> per argument the call actually
#| carried. An argument that is present but is not a string is kept, with an
#| B<undefined> C<path>: it is a location the engine cannot read, which is a
#| very different thing from a location the call did not name — and a caller
#| that conflates the two fails open on exactly the calls it should not.
#|
#| C<$args> is the parsed arguments object; anything else (including the
#| sentinel for arguments that would not parse) yields the empty list.
our sub located-args(Str:D $name, $args, %path-params, $root --> List:D) is export {
	return ().List unless $args.defined && $args ~~ Associative;

	my %arguments = $args.Hash;
	my @out;

	for path-params-for($name, %path-params).list -> $param {
		next unless %arguments{$param}:exists;
		my $value = %arguments{$param};
		@out.push: %( param => $param, value => $value, path => absolutize($value, $root) );
	}

	@out.List;
}

#| A relative argument, measured from the tool's root. Joined as strings rather
#| than parsed and re-rendered: C<'../x'> must survive as C<'../x'> so that the
#| containment test can refuse it, instead of being quietly normalised into an
#| escape. A non-string value, and any value with no root to measure from, comes
#| back as it went in (an undefined C<Str> in the first case).
#|
#| A value that names its own starting point is never joined onto the root:
#| C</x>, and on Windows C<C:\x>, C<C:x>, C<\x> and C<\\host\share\x>. Joining
#| one would bury a second volume inside the root's path -- C<D:/x> under
#| C<C:/work> once came out as C<C:/work/D:/x>, which is under C<C:/work>.
our sub absolutize($value, $root --> Str) is export {
	return Str unless $value ~~ Str:D;
	return $value.Str unless $root ~~ Str:D && $root.chars;
	return $value.Str if self-rooted($value.Str);
	# Under a Windows root the result is spelt with the root's own
	# separator throughout. Both separators mean the same there, so this
	# changes no answer; it is what makes a lease or a prompt read as the
	# path the user would type (C:\work\notes.md, not C:\work/notes.md).
	my %r = parse-path($root);
	if %r<ok> && %r<volume>.chars {
		my Str $sep = $root.contains('\\') ?? '\\' !! '/';
		my Str $rel = $value.trans(['/', '\\'] => [$sep, $sep]);
		return $root.ends-with('/') || $root.ends-with('\\')
			?? $root ~ $rel !! $root ~ $sep ~ $rel;
	}
	$root.ends-with('/') || $root.ends-with('\\') ?? $root ~ $value !! $root ~ '/' ~ $value;
}

my sub self-rooted(Str:D $value --> Bool:D) {
	so $value.starts-with('/') || $value.starts-with('\\') || $value ~~ / ^ <[A..Za..z]> ':' /;
}

my sub common-prefix(@lists --> List:D) {
	return ().List unless @lists;
	my @common = @lists[0].list;
	for @lists.skip -> @other {
		my $at = 0;
		$at++ while $at < @common.elems && $at < @other.elems && @common[$at] eq @other[$at];
		@common = @common.head($at);
	}
	@common.List;
}

# === Hosts ===

# Every URL argument of a call: one { param, value, host } per argument the call
# actually carried, with an undefined `host` for one the engine could not read.
# The same distinction located-args draws, and for the same reason -- a url that
# is present but unreadable is not a call that named no url, and a caller that
# conflates the two fails open on exactly the calls it should not.
my sub url-args($args --> List:D) {
	return ().List unless $args.defined && $args ~~ Associative;

	my %arguments = $args.Hash;
	my @out;

	for DEFAULT-URL-PARAMS.list -> $param {
		next unless %arguments{$param}:exists;
		my $value = %arguments{$param};
		@out.push: %( param => $param, value => $value, host => url-host($value) );
	}

	@out.List;
}

# One call's host against one rule's host pattern: 'yes', 'no', or 'unknown' when
# there was no host to read.
my sub host-verdict($pattern, $host --> Str:D) {
	return 'unknown' unless $host ~~ Str:D && $host.chars;
	match-host($pattern, $host) ?? 'yes' !! 'no';
}

# The one site a permission prompt may offer to scope an "always" answer to. One
# readable host and no other: a call that named none, or named two different ones
# (which today's single `url` parameter cannot, but a future one might), has no
# single site a human could be asked about honestly.
my sub suggestible-host(@urls --> Str) {
	my @hosts = @urls.map({ $_<host> }).grep({ $_ ~~ Str:D && $_.chars }).unique;
	@hosts.elems == 1 ?? @hosts[0] !! Str;
}

# === Commands ===

# Fold a predicate's per-item tri-state verdicts into whether the rule fires and
# whether it did so only on something it could not evaluate. The one place the
# fail-closed asymmetry lives: an allow needs every item 'yes'; a deny or ask
# fires on any 'yes' or 'unknown'. Callers guarantee @verdicts is never empty.
my sub dimension-verdict(Bool $allow, @verdicts --> Hash:D) {
	my $yes = ?@verdicts.grep(* eq 'yes');
	my $unknown = ?@verdicts.grep(* eq 'unknown');
	my $fires = $allow ?? !@verdicts.grep(* ne 'yes') !! ($yes || $unknown);
	my $by-unknown = !$allow && $fires && !$yes;
	%( :$fires, :$by-unknown, saw-unknown => $unknown );
}

# The names of a tool's program and argv parameters: the command/args
# convention, unless a command-params entry overrides one or both. Most specific
# matching pattern wins, as with path-params.
my sub command-params-for(Str:D $name, %command-params --> List:D) {
	my $best-pattern = Str;
	my %best;

	for %command-params.kv -> $pattern, $spec {
		next unless match-tool($pattern, $name);
		next if $best-pattern.defined
			&& !more-specific({ tool => $pattern, decision => 'ask' },
				{ tool => $best-pattern, decision => 'ask' });
		$best-pattern = $pattern;
		%best = $spec ~~ Associative ?? $spec.Hash !! %();
	}

	my $cmd  = %best<command>:exists ?? %best<command> !! DEFAULT-COMMAND-PARAMS<command>;
	my $args = %best<args>:exists    ?? %best<args>    !! DEFAULT-COMMAND-PARAMS<args>;
	($cmd, $args).List;
}

# The commands a call effectively runs, for command-predicate matching. The
# call's literal argv is extracted here — the program and its argument tokens,
# read only as far as the engine can (a non-string token seals the tail off) —
# and handed to the decomposer, which strips wrappers and, when the program is
# a shell run with C<-c>, lexes the payload into the commands really run. Each
# element is a hash of C<program> (the normalised basename, undefined when the
# program cannot be identified), C<tokens> (the literal argv tail), C<sealed>
# (whether C<tokens> is the whole tail) and C<redirect-targets>. An empty list
# means the call named no command at all.
# Whether this call is one a command or check predicate has no business
# speaking about at all: its arguments are readable, it names something, and
# what it names includes neither the program slot nor the argv slot. `sh_poll`
# and its siblings name a job handle and can run nothing, so "deny sh_* where
# the command writes config" is not a question about them.
#
# Three things deliberately answer False and stay unevaluable, because for each
# of them a command really might be hiding:
#
#   * arguments that could not be read at all;
#   * an EMPTY argument object — we have been shown nothing, which is not the
#     same as being shown a call that runs nothing;
#   * a call carrying either slot, even unreadably (a non-string `command`, or
#     an `args` list with no `command`).
#
# The slot names are the ones command-params resolves for this tool, so a tool
# that names its program unusually is described by declaring it there rather
# than by being guessed at here.
my sub call-omits-command(Str:D $name, $args, %command-params --> Bool) {
	return False unless $args.defined && $args ~~ Associative;
	my %arguments = $args.Hash;
	return False unless %arguments.elems;
	my ($cmd-param, $args-param) = command-params-for($name, %command-params);
	!(%arguments{$cmd-param}:exists) && !(%arguments{$args-param}:exists);
}

my sub effective-commands(Str:D $name, $args, %command-params --> List:D) {
	return ().List unless $args.defined && $args ~~ Associative;

	my %arguments = $args.Hash;
	my ($cmd-param, $args-param) = command-params-for($name, %command-params);
	return ().List unless %arguments{$cmd-param}:exists;

	my $program = %arguments{$cmd-param};
	return ( %( program => Str, tokens => ().List, sealed => False, redirect-targets => ().List ), ).List
		unless $program ~~ Str:D && $program.chars;

	my @argv = $program;
	my $sealed = True;
	if %arguments{$args-param}:exists {
		my $raw = %arguments{$args-param};
		if $raw ~~ Positional {
			for $raw.list -> $t {
				if $t ~~ Str:D                       { @argv.push: $t }
				elsif $t ~~ Numeric:D && $t !~~ Bool { @argv.push: $t.Str }
				else { $sealed = False; last }   # a token the engine cannot read ends the visible tail
			}
		}
		else {
			$sealed = False;   # an argv that is not a list is unreadable past here
		}
	}

	MCP::Client::Policy::Commands::decompose-argv(@argv, :$sealed);
}

# One command against one rule's command predicate: 'yes', 'no', or 'unknown'.
# 'no' means the rule definitely does not speak about this command; 'unknown'
# means it might, but an unreadable argv tail keeps the engine from confirming.
my sub command-verdict(%rule, %cmd --> Str:D) {
	return 'unknown' unless %cmd<program>.defined;
	# Deny/ask fold case (catch `RM` for `rm` on a case-insensitive host); allow
	# stays exact so it never grants a differently-cased binary.
	my $fold = (%rule<decision> // '') ne 'allow';
	return 'no' unless match-command(%rule<command>, %cmd<program>, :$fold);

	my @tokens = %cmd<tokens>.list;
	my $sealed = so %cmd<sealed>;
	my @sub;

	@sub.push: args-prefix-verdict(%rule<args>.list, @tokens, $sealed)  if %rule<args>:exists;
	@sub.push: args-any-verdict(%rule<args-any>.list, @tokens, $sealed) if %rule<args-any>:exists;

	# A rule's sub-predicates are ANDed: any definite miss is a miss, and short
	# of that an unconfirmable one keeps the whole verdict unknown.
	return 'no' if @sub.grep(* eq 'no');
	return 'unknown' if @sub.grep(* eq 'unknown');
	'yes';
}

# The rule's leading argv tokens must match the command's, in order. Running
# past what the engine can read is 'no' when the argv is sealed (it really is
# shorter) and 'unknown' when it is not (the tail might continue the prefix).
my sub args-prefix-verdict(@need, @tokens, Bool $sealed --> Str:D) {
	for @need.kv -> $i, $want {
		if $i < @tokens.elems {
			return 'no' unless @tokens[$i] eq $want;
		}
		else {
			return $sealed ?? 'no' !! 'unknown';
		}
	}
	'yes';
}

# At least one of the rule's tokens appears somewhere in the argv. Absent from
# the visible tokens, it is 'no' on a sealed argv and 'unknown' otherwise.
my sub args-any-verdict(@any, @tokens, Bool $sealed --> Str:D) {
	return 'yes' if @tokens.grep(-> $t { so @any.grep(* eq $t) });
	$sealed ?? 'no' !! 'unknown';
}

# One effective command against a named policy-supplied check: 'yes', 'no', or
# 'unknown'. A check the policy did not supply, or one that answers with
# anything other than the three verdicts, is unevaluable — and unevaluable fails
# closed (allow can't fire, deny/ask do).
my sub run-check(%checks, Str:D $name, %cmd --> Str:D) {
	my $check = %checks{$name};
	return 'unknown' unless $check ~~ Callable;
	my $v = $check(%cmd);
	($v ~~ Str:D && ($v eq 'yes' || $v eq 'no' || $v eq 'unknown')) ?? $v !! 'unknown';
}

# === Specificity ===

# How concretely a rule speaks about a call, most concrete first: an exact tool
# name beats a glob, a longer glob beats a shorter one, a rule with a path
# predicate beats a blanket one, and a deeper predicate beats a shallower one.
# Used only to decide which of several rules that agree gets reported -- the
# decision itself is settled by deny > ask > allow, which no ordering can
# disturb.
my sub specificity(%rule --> List:D) {
	my $tool = %rule<tool>;
	my $tool-glob = $tool.ends-with('*');

	my $has-command = %rule<command>:exists;
	my $cmd = $has-command ?? %rule<command> !! '';
	my $cmd-glob = $has-command && $cmd.ends-with('*');
	my $args-len = (%rule<args> // ()).elems + (%rule<args-any> // ()).elems;

	my $has-under = %rule<under>:exists;
	my $depth = $has-under ?? parse-path(%rule<under>)<segments>.elems !! 0;

	# A host narrows as `under` does -- a rule about one site speaks more
	# concretely than one about the tool -- and an exact host beats a suffix glob,
	# a longer glob a shorter, exactly as a command pattern does.
	my $has-host = %rule<host>:exists;
	my $host = $has-host ?? %rule<host> !! '';
	my $host-glob = $has-host && $host.starts-with('*.');

	(
		$tool-glob ?? 0 !! 1,
		$tool-glob ?? $tool.chars - 1 !! $tool.chars,
		$has-command ?? 1 !! 0,
		($has-command && !$cmd-glob) ?? 1 !! 0,
		$has-command ?? ($cmd-glob ?? $cmd.chars - 1 !! $cmd.chars) !! 0,
		$args-len,
		%rule<check>:exists ?? 1 !! 0,
		$has-under ?? 1 !! 0,
		$depth // 0,
		$has-host ?? 1 !! 0,
		($has-host && !$host-glob) ?? 1 !! 0,
		$has-host ?? ($host-glob ?? $host.chars - 2 !! $host.chars) !! 0,
	).List;
}

my sub more-specific(%a, %b --> Bool:D) {
	my @a = specificity(%a);
	my @b = specificity(%b);

	for ^@a -> $i {
		return True if @a[$i] > @b[$i];
		return False if @a[$i] < @b[$i];
	}

	False;
}
