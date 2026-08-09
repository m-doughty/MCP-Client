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

A rule is JSON-safe plain data with three members, one of them optional:

=begin code :lang<raku>
{ tool => 'fs_read', decision => 'allow' }                        # bare
{ tool => 'fs_*',    decision => 'deny', under => '/etc' }        # with a predicate
=end code

=item C<tool> — an exact tool name, or a prefix glob: a name ending in C<*>
      matches every name that starts with what comes before it. C<*> on its own
      matches everything. A C<*> anywhere else is refused, because a rule that
      silently matches nothing is worse than one that will not load.
=item C<decision> — C<allow>, C<deny> or C<ask>.
=item C<under> — a directory. The rule only has an opinion about calls whose
      location arguments are inside it.

Anything else in a rule is refused as well: C<dir> where C<under> was meant
would otherwise turn a narrow rule into a blanket one, which is exactly the
mistake a permission system must not make quietly.

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
=item a null byte, or a backslash — on a Windows server C<\> is a separator and
      on a POSIX one it is an ordinary character, and guessing wrong either
      hides an escape or invents one. Write rules and roots with C</>, which
      Windows accepts too;
=item an absolute path measured against a relative directory, or the reverse:
      no root was configured, so there is nothing to measure from;
=item an argument that is missing, or is not a string at all.

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

=end pod

use MCP::Client::Exceptions;

unit module MCP::Client::Policy::Rules;

# The alphabet a tool name is made of: MCP::Server's own, and the one the
# OpenAI-compatible function-calling APIs accept. A rule naming a tool that
# could never exist is a typo, and a typo in a permission file is a rule that
# never fires.
my $TOOL-ALPHABET = rx/^ <[A..Za..z0..9_-]>* $/;

my constant RULE-KEYS = <tool decision under>.Set;
my constant DECISIONS = <allow deny ask>.Set;

# The location arguments of a tool, unless told otherwise. The FileSystem pack
# names its location parameters exactly this, on purpose.
my constant DEFAULT-PATH-PARAMS = <path from to>;

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
			~ 'tool, decision and an optional under',
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

	%rule;
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

		%out{$pattern} = $named.map(*.Str).List;
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

#| Whether C<$path> is inside C<$dir>: C<'yes'>, C<'no'>, or C<'unknown'> when
#| the question cannot be answered by looking at the two strings. Purely
#| lexical, segment by segment; a directory is inside itself.
our sub path-under($dir, $path --> Str:D) is export {
	my %d = parse-path($dir);
	my %p = parse-path($path);
	return 'unknown' unless %d<ok> && %p<ok>;
	return 'unknown' unless %d<absolute> eqv %p<absolute>;

	my @dir = %d<segments>.list;
	my @in = %p<segments>.list;
	return 'no' if @in.elems < @dir.elems;

	@in.head(@dir.elems).List eqv @dir.List ?? 'yes' !! 'no';
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
our sub evaluate(
	@rules, $tool, $args, :%roots, :%path-params
	--> Hash:D
) is export {
	my $name = $tool ~~ Str:D ?? $tool !! '';
	my $root = root-for($name, %roots);
	my @located = located-args($name, $args, %path-params, $root);
	my @paths = @located.map({ $_<path> }).grep({ $_ ~~ Str:D }).List;

	my %won;                # decision => { rule, by-unknown }
	my Bool $saw-unknown = False;

	for @rules.list -> $raw {
		next unless $raw ~~ Associative;
		my %rule = $raw.Hash;
		next unless DECISIONS{%rule<decision> // ''};
		next unless match-tool(%rule<tool>, $name);

		my $fires = True;
		my $by-unknown = False;

		if %rule<under>:exists {
			# The rule's directory is measured from the same root the call's
			# arguments are, so a rule may be written relative to the sandbox it
			# is about.
			my $under = absolutize(%rule<under>, $root);

			# No location arguments at all is not "nothing to object to": it is a
			# predicate that could not be evaluated, and those go the safe way.
			my @verdicts = @located
				?? @located.map({ path-under($under, $_<path>) }).List
				!! ('unknown',);

			my $yes = ?@verdicts.grep(* eq 'yes');
			my $unknown = ?@verdicts.grep(* eq 'unknown');
			$saw-unknown = True if $unknown;

			if %rule<decision> eq 'allow' {
				$fires = !@verdicts.grep(* ne 'yes');
			}
			else {
				$fires = $yes || $unknown;
				$by-unknown = $fires && !$yes;
			}
		}

		next unless $fires;

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
		suggestion => suggest($name, @paths, $root),
	};
}

#| The rule a permission prompt offers as its "always allow" / "always deny":
#| the tool, plus the deepest directory containing every path the call names,
#| clamped to the tool's configured root. C<under> is left out entirely when no
#| directory can be named lexically.
our sub suggest(Str:D $tool, @paths, $root --> Hash:D) is export {
	my %suggestion = tool => $tool;

	my @parsed = @paths.map({ parse-path($_) }).grep({ $_<ok> });
	return %suggestion unless @parsed;
	return %suggestion unless @parsed.map({ $_<absolute> }).unique.elems == 1;

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
	my $dir = render-path($absolute, @common);
	return %suggestion unless $dir.chars;

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

# One path, taken apart lexically. `ok` is False whenever the string cannot be
# reasoned about at all, with `reason` saying which way it was hopeless -- the
# tri-state's `unknown` and validate-rule's error message both come from here,
# so the two can never disagree about what a usable path is.
my sub parse-path($value --> Hash:D) {
	return %( ok => False, reason => 'not-a-string' ) unless $value ~~ Str:D;

	my $raw = $value.Str;
	return %( ok => False, reason => 'empty' ) unless $raw.chars;
	return %( ok => False, reason => 'null-byte' ) if $raw.contains("\0");
	return %( ok => False, reason => 'backslash' ) if $raw.contains('\\');

	# Empty segments (a doubled or trailing slash) and '.' carry no meaning;
	# '..' carries too much of it to guess at.
	my @segments = $raw.split('/').grep({ $_ ne '' && $_ ne '.' });
	return %( ok => False, reason => 'traversal' ) if @segments.grep(* eq '..');

	%( ok => True, reason => '', absolute => $raw.starts-with('/'), segments => @segments.List );
}

my sub render-path(Bool() $absolute, @segments --> Str:D) {
	($absolute ?? '/' !! '') ~ @segments.join('/');
}

my sub path-complaint(Str:D $reason --> Str:D) {
	given $reason {
		when 'not-a-string' { 'a directory must be a string' }
		when 'empty'        { 'a directory cannot be empty' }
		when 'null-byte'    { 'a path may not contain a null byte' }
		when 'backslash'    { "a path may not contain a backslash: write directories with '/', "
			~ 'which Windows accepts too' }
		when 'traversal'    { "a path may not contain a '..' segment, which only the server could resolve" }
		default             { 'it is not a usable path' }
	}
}

# The root a tool's relative arguments are measured from: the longest matching
# tool-name prefix, so 'fs' and 'fs_ext' may both have one and '' is a
# catch-all. Prefixes rather than globs, and deliberately: a root is about
# where a whole family of tools lives, not about matching names.
my sub root-for(Str:D $name, %roots --> Str) {
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

# The names of a tool's location arguments: the convention, unless a
# path-params entry overrides it. The most specific matching pattern wins, by
# the same ordering rules that pick between two matching rules.
my sub path-params-for(Str:D $name, %path-params --> List:D) {
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

# Every location argument of a call, in the order the tool's parameters are
# declared in. An argument that is present but is not a string is kept, with an
# undefined path: it is a location the engine cannot read, which is a very
# different thing from a location the call did not name.
my sub located-args(Str:D $name, $args, %path-params, $root --> List:D) {
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

# A relative argument, measured from the tool's root. Joined as strings rather
# than parsed and re-rendered: '../x' must survive as '../x' so that parse-path
# can refuse it, instead of being quietly normalised into an escape.
my sub absolutize($value, $root --> Str) {
	return Str unless $value ~~ Str:D;
	return $value.Str unless $root ~~ Str:D && $root.chars;
	return $value.Str if $value.starts-with('/');
	$root.ends-with('/') ?? $root ~ $value !! $root ~ '/' ~ $value;
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

# === Specificity ===

# How concretely a rule speaks about a call, most concrete first: an exact tool
# name beats a glob, a longer glob beats a shorter one, a rule with a path
# predicate beats a blanket one, and a deeper predicate beats a shallower one.
# Used only to decide which of several rules that agree gets reported -- the
# decision itself is settled by deny > ask > allow, which no ordering can
# disturb.
my sub specificity(%rule --> List:D) {
	my $tool = %rule<tool>;
	my $glob = $tool.ends-with('*');
	my $depth = %rule<under>:exists ?? parse-path(%rule<under>)<segments>.elems !! 0;

	(
		$glob ?? 0 !! 1,
		$glob ?? $tool.chars - 1 !! $tool.chars,
		%rule<under>:exists ?? 1 !! 0,
		$depth // 0,
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
