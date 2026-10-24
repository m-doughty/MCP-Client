=begin pod

=head1 NAME

MCP::Client::Policy::Floor - the danger floor: a fixed, auditable set of rules
for the operations that are dangerous no matter who asked

=head1 DESCRIPTION

The danger floor is a permission posture no preset relaxes: the handful of
operations that destroy work, hand over the machine, or let the agent edit its
own permissions. It is deliberately a plain rule list plus a few named
predicates — never a classifier — so it can be read, tested and reasoned about
line by line.

Two pieces plug into a C<MCP::Client::Policy>:

=item C<danger-floor(...)> returns the rules, in the ordinary
      C<MCP::Client::Policy::Rules> schema. Prepend them to a policy's rules
      (they are just data). Most are expressible as command/args matches; the
      few that need to look at I<what a command targets> carry a C<check>.
=item C<floor-checks(...)> returns the C<checks> map those C<check> rules name —
      the target analysis for C<rm>, and the shell-redirect analysis for writes
      to protected files. These are code, passed to the policy as C<checks>.

=head2 The split

Almost everything asks (grantable, but the prompt is shown in red because each
rule carries C<severity =E<gt> 'danger'> and a C<note> saying why). Only two
things are a hard C<deny> that even the bypass preset cannot waive: a recursive
delete of the filesystem root or your home directory, and a write to the
agent's own policy/config. Everything else — force-pushes, C<reset --hard>,
C<sudo>, C<curl | sh>, C<shutdown>, C<dd> — is a red ask.

=head2 What the floor leaves to the sandbox

The write checks are lexical and best-effort: they resolve C<~>, C<~user> and
C<..>, and read both redirection targets and path arguments (so C<tee>, C<cp>
and C<sed -i> are caught as well as C<E<gt>>). Three shapes they deliberately do
B<not> catch, because the target is not knowable lexically, are left to the OS
sandbox layer (which makes C<$SADNA_HOME> read-only): a redirect to an
unreadable variable (C<E<gt> $CFG>), a purely relative path (no working
directory to measure from), and a glob whose expansion is unknown
(C<E<gt> ~/.sadna/conf*> — the literal prefix is under the config dir, but the
decomposer drops the whole word once any part of it expands). The floor is the
approval layer; the sandbox is the containment layer, and the two are meant to
be composed.

=head2 Every spelling of a path

The floor only ever denies or asks, so where a path could be read two ways it
takes both, and a target that matches on either reading is caught. On every
host — the strings are what is compared, not the disk — it understands:

=item drive paths with either separator (C<C:\Users\me>, C<c:/users/ME>), UNC
      shares (C<\\server\share\x>, C<//server/share/x>), Git Bash's C</c/…> for
      drive C, and a drive-less C<\x> or C</x> on the home's drive;
=item an admin share as the drive it is, whatever the host is called:
      C<\\localhost\C$\Users\me>, C<\\127.0.0.1\c$\…> and the machine's own
      name are all C<C:\Users\me>;
=item the paths that skip Windows' own normalisation: C<\\?\C:\…>,
      C<\\.\C:\…>, C<//?/C:/…> and C<\\?\UNC\server\share\…> are the drive or
      share they name, and a C<\\?\Volume{…}> or C<\\?\GLOBALROOT\…> path, whose
      volume the floor cannot place, is taken to be on any volume;
=item names as NTFS reads them: case-folded, a trailing dot or space dropped,
      an alternate-data-stream suffix ignored, and an 8.3 short name
      (C<SADNA~1>, C<ME~1>) matched against every long name it could have been
      given;
=item a backslash in a path with no Windows volume both ways — as the
      separator it is on Windows and as the filename character it is on POSIX —
      so C</home/me/.sadna/agents/x\..\..\..\..\evil.md> is still a write
      inside C<.sadna>.

A home is often spelt more than one way on Windows (C<%USERPROFILE%>,
C<%HOMEDRIVE%%HOMEPATH%>, a Git Bash C<HOME>), so C<home> may be a list, and
every spelling in it is protected.

What the floor does B<not> chase is an alias somebody made: a symbolic link, a
junction, a C<subst> or mapped drive, a share pointing somewhere other than a
drive root. Those are the OS sandbox's to contain, as the shapes above are.

=head1 SYNOPSIS

=begin code :lang<raku>
use MCP::Client::Policy;
use MCP::Client::Policy::Floor;

my $home  = %*ENV<HOME>;
my $sadna = "$home/.sadna";

my $policy = MCP::Client::Policy.new(
    :$provider,
    rules  => [ |danger-floor(:$home, sadna-home => $sadna), |@my-rules ],
    checks => floor-checks(:$home, sadna-home => $sadna),
);
=end code

=end pod

use MCP::Client::Policy::Commands;
use MCP::Client::Policy::Rules;

unit module MCP::Client::Policy::Floor;

# Shell startup files: writing one of these plants code that runs later, outside
# this call's sandbox. Matched by basename, so an absolute or relative target
# is caught alike.
my constant RC-FILES = set(
	'.bashrc', '.bash_profile', '.bash_login', '.bash_logout', '.profile',
	'.zshrc', '.zshenv', '.zprofile', '.zlogin', '.zlogout',
	'.kshrc', '.mkshrc', '.cshrc', '.tcshrc', '.inputrc', '.login',
);

# The interpreters a bare invocation of (no `-c`, so reading stdin or a script)
# is arbitrary code — the `curl | sh` shape surfaces one of these.
my constant BARE-INTERPRETERS = <sh bash zsh dash ksh mksh ash>;

#| The danger-floor rules, in the policy rule schema. C<home> and C<sadna-home>
#| parameterise the target checks (pass the same values to C<floor-checks>,
#| which says what they may be).
our sub danger-floor(:$home, :$sadna-home --> List:D) is export {
	my @rules;

	# %( … ) not { … }: a block that opens with a `|`-slip is a closure, not a
	# hash, and evaluate would skip it as non-Associative.
	my sub ask($note, *%rule)  { @rules.push: %( |%rule, decision => 'ask',  severity => 'danger', :$note ) }
	my sub deny($note, *%rule) { @rules.push: %( |%rule, decision => 'deny', severity => 'danger', :$note ) }

	# --- Filesystem destruction ---
	deny('a recursive delete of the filesystem root or your home directory',
		tool => 'sh_*', command => 'rm', check => 'rm-destroy-root');
	ask('a recursive delete of a target the agent could not read (a variable or a glob)',
		tool => 'sh_*', command => 'rm', check => 'rm-destroy-unverifiable');
	ask('formats a filesystem, erasing everything on it',
		tool => 'sh_*', command => 'mkfs*');
	ask('dd can overwrite a whole disk or partition',
		tool => 'sh_*', command => 'dd');
	ask('wipefs erases filesystem signatures from a device',
		tool => 'sh_*', command => 'wipefs');

	# --- Git history / state destruction ---
	# A check, not an args prefix: `git -C /repo push --force` puts a global
	# option before the subcommand, which a prefix anchored at argv[0] misses.
	ask('a destructive git operation (force-push, reset --hard, clean, or stash clear/drop)',
		tool => 'sh_*', command => 'git', check => 'git-danger');

	# --- Privilege escalation ---
	for <sudo doas su pkexec run0> -> $c {
		ask('runs a command with elevated privileges', tool => 'sh_*', command => $c);
	}

	# --- System control ---
	for <shutdown reboot halt poweroff> -> $c {
		ask('powers off or restarts the machine', tool => 'sh_*', command => $c);
	}

	# --- Remote code execution (curl | sh surfaces a bare interpreter) ---
	for BARE-INTERPRETERS -> $c {
		ask('runs code read from stdin or a script file, e.g. a piped `curl | sh`',
			tool => 'sh_*', command => $c);
	}

	# --- Self-modification: the agent editing its own permissions ---
	deny("writes to the agent's own policy or configuration",
		tool => 'sh_*', check => 'writes-config');
	ask('writes to a shell startup file or a .git directory, which run code later',
		tool => 'sh_*', check => 'writes-sensitive');

	@rules.List;
}

#| The checks the C<check>-bearing floor rules name. Pass as C<checks> to the
#| policy alongside C<danger-floor>'s rules.
#|
#| C<home> is the home directory a recursive delete may not take and C<~>
#| expands to: one path, or a list of every spelling of it the host has (on
#| Windows C<%USERPROFILE%>, C<%HOMEDRIVE%%HOMEPATH%> and C<HOME> can each name
#| a different directory, and the floor protects all of them). Undefined, or
#| an empty list, is no home: C<~> then stays unexpanded and only a delete of
#| C<~> itself is caught. Anything else dies — a home the floor silently
#| ignored would be a home it silently stopped protecting.
our sub floor-checks(:$home, :$sadna-home --> Hash:D) is export {
	my @homes     = home-list($home);
	my $sadna-dir = normalize-dir($sadna-home);

	{
		'rm-destroy-root'         => -> %cmd { rm-destroy(%cmd, @homes, :root) },
		'rm-destroy-unverifiable' => -> %cmd { rm-destroy(%cmd, @homes, :unverifiable) },
		'git-danger'              => -> %cmd { git-danger(%cmd) },
		'writes-config'           => -> %cmd { writes-config(%cmd, @homes, $sadna-dir) },
		'writes-sensitive'        => -> %cmd { writes-sensitive(%cmd) },
	}
}

# The homes floor-checks was given, as a list of non-empty paths (see its
# doc). Duplicates are dropped; the order is kept.
my sub home-list($home --> List:D) {
	return ().List without $home;
	my @given = $home ~~ Str:D ?? ($home,) !! do {
		die "the danger floor's home must be a path or a list of paths, not a {$home.^name}"
			unless $home ~~ Positional;
		$home.list;
	};
	for @given -> $h {
		die "the danger floor's home must be a path or a list of paths, but the list holds "
			~ ($h.defined ?? "a {$h.^name}" !! "an undefined {$h.^name}")
			unless $h ~~ Str:D;
	}
	@given.grep(*.chars).map(&normalize-dir).unique.List;
}

# === Checks ===

# Recursive rm at a catastrophic (root, :root) or an unreadable (:unverifiable)
# target. 'yes' fires the rule, 'no' passes it by, 'unknown' fails closed.
my sub rm-destroy(%cmd, @homes, :$root, :$unverifiable --> Str:D) {
	return 'unknown' unless %cmd<program>.defined;
	return 'no' unless %cmd<program>.fc eq 'rm';   # fold: catch `RM` on a case-insensitive host
	my @tokens = %cmd<tokens>.list;
	return 'no' unless is-recursive(@tokens);

	if $root {
		# A literal target that is the filesystem root or the home directory.
		return 'yes' if @tokens.grep({ !.starts-with('-') && catastrophic-target($_, @homes) });
		return 'no';
	}
	# :unverifiable — the argv could not be read to the end, so the real target
	# might be anything (a $VAR, a glob). A concrete, safe path stays 'no'.
	return 'yes' unless %cmd<sealed>;
	'no';
}

# Git global options that take a separate value, so the token after them is not
# the subcommand: `git -C /repo push` … Anything else starting with `-` is a
# valueless global (`-p`, `--no-pager`, `--bare`, `--git-dir=…`) we skip too.
# The complete set of git 2.49 top-level globals that take a SEPARATE value
# token (so the token after them is not the subcommand). A version-coupled
# denylist — a future git global that takes a value reopens the gap.
my constant GIT-GLOBAL-VALUED = set(
	'-C', '-c', '--git-dir', '--work-tree', '--namespace', '--exec-path',
	'--config-env', '--super-prefix', '--attr-source', '--shallow-file',
);

# A destructive git operation, found past any leading global options.
my sub git-danger(%cmd --> Str:D) {
	return 'unknown' unless %cmd<program>.defined;
	return 'no' unless %cmd<program>.fc eq 'git';

	my @tokens = %cmd<tokens>.list;
	my $sealed = so %cmd<sealed>;

	# Skip global options to reach the subcommand.
	my $i = 0;
	while $i < @tokens.elems && @tokens[$i].starts-with('-') {
		$i++ if GIT-GLOBAL-VALUED{@tokens[$i]};   # this option also eats its value
		$i++;
	}
	# Ran off the end before a subcommand: unknown if the argv was truncated
	# (the subcommand might be in the unreadable tail), otherwise a bare git.
	return ($sealed ?? 'no' !! 'unknown') if $i >= @tokens.elems;

	my $sub = @tokens[$i];
	my @rest = @tokens[$i + 1 .. *];
	my $rest-sealed = $sealed;   # were all of @rest readable?

	given $sub {
		when 'push' {
			return 'yes' if @rest.grep({ $_ eq '--force' || $_ eq '-f' || $_ eq '--force-with-lease'
				|| ($_.starts-with('-') && !$_.starts-with('--') && $_.contains('f')) });
			return 'unknown' unless $rest-sealed;   # the force flag may be in the unreadable tail
			return 'no';
		}
		when 'reset' {
			return 'yes' if @rest.grep(* eq '--hard');
			return 'unknown' unless $rest-sealed;
			return 'no';
		}
		when 'clean' { return 'yes' }   # any git clean deletes untracked files
		when 'stash' {
			return 'yes' if @rest.grep({ $_ eq 'clear' || $_ eq 'drop' });
			return 'no';
		}
		default { return 'no' }
	}
}

# A path the agent's own policy/config lives under, touched by this command: a
# hard deny. Best-effort and lexical — the filesystem pack's own sandbox is the
# primary guard for the fs tools, and the OS sandbox (module 8 phase 6) is the
# robust guard for the shell; this catches the obvious shell path in between.
# We check redirection targets AND the command's own path arguments, because a
# `tee ~/.sadna/config`, `cp x ~/.sadna/config` or `sed -i ~/.sadna/config`
# writes just as a `> ~/.sadna/config` does. Fires only on a clear lexical
# match, so an unresolvable path is left to the sandbox rather than over-denied.
my sub writes-config(%cmd, @homes, $sadna --> Str:D) {
	# `.defined` first: a floor built without a sadna-home leaves this a Str
	# type object, and `.chars` on one warns into whatever the host is drawing
	# on. There is no config path to protect in that case, so the answer is the
	# same 'no' either way — quietly.
	return 'no' unless $sadna.defined && $sadna.chars;
	my @config = anchor-spellings(path-readings($sadna, @homes));
	return 'no' unless @config;
	for candidate-paths(%cmd) -> $raw {
		# Resolve tilde and collapse `.`/`..`/`//` first, so an obfuscated
		# `~/x/../.sadna/config` cannot slip past. A path we cannot resolve to
		# an absolute form (purely relative, or an unreadable token) is left to
		# the OS sandbox (module 8 phase 6 makes $SADNA_HOME read-only) rather
		# than over-denied.
		for path-readings($raw, @homes) -> %target {
			return 'yes' if @config.first({ same-place-under($_, %target) }).defined;
		}
	}
	'no';
}

# Whether the normalised path %in names %dir or something inside it, as the
# floor reckons it. The floor only ever denies, so it errs towards a match:
#
# =item segments compare case-folded -- the shell's targets are the LOCAL
#   filesystem, case-insensitive on macOS and Windows;
# =item a segment compares as NTFS reads it: a trailing dot or space dropped
#   (`.sadna.` IS `.sadna`), an alternate-data-stream suffix ignored
#   (`config.json:x` writes into `config.json`), and an 8.3 short name taken
#   for any long name it could have been given (`SADNA~1` for `.sadna`);
# =item on a Windows drive, two more spellings of the same place count: the
#   MSYS/Git Bash `/c/Users/me` for `C:\Users\me`, and a drive-less `/Users/me`
#   or `\Users\me`, which Windows resolves on the current drive;
# =item a volume the floor could not place (`*`: a `\\?\Volume{…}` or a
#   `\\?\GLOBALROOT\…` path) may be any volume.
my sub same-place-under(%dir, %in --> Bool:D) {
	for (%in, |windows-spellings(%in, %dir)) -> %p {
		next unless same-volume(%p<volume>, %dir<volume>);
		my @d = %dir<segs>.list;
		my @p = %p<segs>.list;
		return True if @p.elems >= @d.elems && segments-match(@d, @p.head(@d.elems));
	}
	False;
}

# The other spellings, on %anchor's drive, of a drive-less root path %n: see
# same-place-under. Empty unless %anchor is on a Windows drive.
my sub windows-spellings(%n, %anchor --> List:D) {
	return ().List unless %anchor<volume> ~~ / ^ <[A..Z]> ':' $ /
		&& %n<kind> eq 'root' && %n<volume> eq '';
	my @s = %n<segs>.list;
	my @out = %( kind => 'root', volume => %anchor<volume>, segs => @s.List ),;
	@out.push: %( kind => 'root', volume => @s[0].uc ~ ':', segs => @s.skip.List )
		if @s && @s[0] ~~ / ^ <[A..Za..z]> $ /;
	@out.List;
}

# The protected places a set of readings names, each spelt every way the floor
# compares against: the readings themselves when they are rooted, and a
# drive-less `/c/…` home (Git Bash's HOME) as drive C as well, so that
# `C:\Users\me` is caught against it.
my sub anchor-spellings(@readings --> List:D) {
	my @out;
	for @readings.grep(*<kind> eq 'root') -> %r {
		@out.push: %r;
		my @s = %r<segs>.list;
		@out.push: %( kind => 'root', volume => @s[0].uc ~ ':', segs => @s.skip.List )
			if %r<volume> eq '' && @s && @s[0] ~~ / ^ <[A..Za..z]> $ /;
	}
	@out.unique(:with(&[eqv])).List;
}

# Two volumes the floor treats as one: the same drive or share, either case;
# or either is one it could not place.
my sub same-volume(Str:D $a, Str:D $b --> Bool:D) {
	$a eq '*' || $b eq '*' || $a.fc eq $b.fc;
}

# Whether two equally long segment lists name the same place: see
# same-segment.
my sub segments-match(@want, @have --> Bool:D) {
	return False unless @want.elems == @have.elems;
	for @want.kv -> $i, $w {
		return False unless same-segment($w, @have[$i]);
	}
	True;
}

# One segment of a protected path against one of a target: the same once both
# are read as NTFS reads a name, or either an 8.3 short name the other's long
# name could have been given.
my sub same-segment(Str:D $want, Str:D $have --> Bool:D) {
	return True if ntfs-name($want) eq ntfs-name($have);
	short-alias($have, $want) || short-alias($want, $have);
}

# One segment as NTFS reads it, case-folded: see same-place-under.
my sub ntfs-name(Str:D $segment --> Str:D) {
	my $name = $segment.subst(/ ':' .* $ /, '').subst(/ <[. ]>+ $ /, '');
	($name.chars ?? $name !! $segment).fc;
}

# Whether $short is an 8.3 short name that Windows (or a Samba server) could
# have given the long name $long. A short name is NAME~N[.EXT]; Windows makes
# NAME from the first letters of the long name once its spaces and dots are
# dropped, upper-cased, with an `_` for each character 8.3 cannot hold -- so
# `SADNA~1` for `.sadna`, `ME~1` for `me`. After a few collisions it falls
# back to two letters and four hex digits of a hash (`SA1B2C~1`), and Samba
# mangles to five letters and a two-character hash (`SADNA~X7`), so a NAME
# ending in four hex digits only needs what comes before them to match. The
# extension is not compared. All of this over-matches, which is the floor's
# safe direction.
my sub short-alias(Str:D $short, Str:D $long --> Bool:D) {
	return False unless MCP::Client::Policy::Rules::windows-short-name($short);
	my $base = $short.split('.').head;
	my $name = $base.substr(0, $base.rindex('~')).uc;
	my $key  = $long.subst(/ ':' .* $ /, '').uc.subst(/ <[.\s]> /, '', :g);
	return True if name-prefix($name, $key);
	$name ~~ / ^ $<lead>=[.*] <[0..9A..F]> ** 4 $ / && name-prefix(~$<lead>, $key);
}

# Whether $key begins with $name, an `_` in $name standing for any character.
my sub name-prefix(Str:D $name, Str:D $key --> Bool:D) {
	return False if $key.chars < $name.chars;
	for ^$name.chars -> $i {
		my $c = $name.substr($i, 1);
		next if $c eq '_';
		return False unless $key.substr($i, 1) eq $c;
	}
	True;
}

# A shell startup file or a .git directory touched by this command — either is
# code that runs later. Same redirect-and-arguments reach as writes-config.
my sub writes-sensitive(%cmd --> Str:D) {
	for candidate-paths(%cmd) -> $raw {
		my @segments = $raw.split(/<[\/\\]>/).grep(*.chars);
		my $base = @segments.tail // $raw;
		return 'yes' if RC-FILES{$base.fc};                  # fold: `.BASHRC` → `.bashrc`
		return 'yes' if @segments.grep(*.fc eq '.git');
	}
	'no';
}

# The paths a command names: its redirection targets, its non-flag argv tokens,
# and the value glued after an `=` in any token — so `--target-directory=/x`,
# `--output=/x` and dd's `of=/x` are seen as the paths they are, not dropped as
# options. A glued short flag with no `=` (`-t/x`) stays ambiguous and is left
# to the sandbox rather than parsing every command's option grammar.
my sub candidate-paths(%cmd --> List:D) {
	my @tokens = %cmd<tokens>.list;
	( %cmd<redirect-targets>.list,
	  @tokens.grep({ !.starts-with('-') }),
	  @tokens.grep(*.contains('=')).map({ .substr(.index('=') + 1) }),
	).flat.grep(*.chars).List;
}

# === Helpers ===

my sub is-recursive(@tokens --> Bool:D) {
	so @tokens.grep({
		$_ eq '--recursive'
			|| (.starts-with('-') && !.starts-with('--') && (.contains('r') || .contains('R')))
	});
}

# Whether a delete target resolves to the filesystem root or the home directory
# once `.`/`..`/`//` are collapsed and `~` is understood — so `//`, `/.`, `/..`,
# `/x/..`, `~/.`, `~//` and the expanded home are all caught, not just the
# bare spellings, and so is every other spelling path-readings knows.
my sub catastrophic-target(Str:D $token, @homes --> Bool:D) {
	my @anchors = anchor-spellings(@homes.map({ |path-readings($_, ()) }));
	for path-readings($token, @homes) -> %n {
		return True if %n<kind> eq 'home' && !%n<segs>;   # the home directory itself
		next unless %n<kind> eq 'root';
		# Each spelling of the target: as written, and on a Windows home also as
		# Git Bash (`/c` is drive C) and as a drive-less path would reach it.
		for (@anchors || (%(),)) -> %h {
			for (%n, |(%h ?? windows-spellings(%n, %h) !! ())) -> %p {
				return True unless %p<segs>;               # a filesystem root (`/`, `C:\`, `/c`, a share)
				# Fold case, and read names as NTFS does: the shell floor's
				# targets are the LOCAL filesystem, which on macOS/Windows is
				# case-insensitive, so `/Users/Bob` IS home. Over-deny on a
				# case-sensitive host is the safe direction.
				return True if %h && same-volume(%p<volume>, %h<volume>)
					&& segments-match(%h<segs>.list, %p<segs>.list);
			}
		}
	}
	False;
}

my constant SEP = / <[\\/]> /;

# Every reading of one path token the floor weighs: a list of
# { kind, volume, segs } hashes (see read-path), usually one. More than one
# when the token could mean more than one place: `~` expands against every
# spelling of home, and a token holding a backslash is read both as Windows
# reads it (a separator) and as POSIX does (an ordinary character) -- so
# `/home/me/.sadna/x\..\..\evil` is inside `.sadna` on the reading that
# keeps it there, as well as outside it on the one that collapses it.
my sub path-readings(Str:D $token, @homes --> List:D) {
	my @out;
	for (@homes || (Str,)) -> $home {
		@out.append: read-path($token, $home);
		@out.append: read-path($token, $home, :posix) if $token.contains('\\');
	}
	@out.unique(:with(&[eqv])).List;
}

# Take a path apart into a list of C<< { kind, volume, segs } >> readings: kind
# is 'root' (absolute), 'home' (tilde- or ~user-rooted, with no absolute home
# to expand it against) or 'rel'. Segments have `.`, empty and `..`
# collapsed. Lexical only; the collapse is safe here because it only ever
# widens what counts as catastrophic (the deny direction).
#
# volume is '' for a POSIX path or a drive-less Windows one, a drive (`C:`), a
# UNC share (`\\host\share`, case-folded) or `*` -- a Windows volume named in
# a way the floor cannot place, which therefore may be any.
#
# Windows paths are understood on every host, and a backslash separates as a
# slash does: a drive (`C:\x`, `C:/x`) or a UNC share (`\\host\share\x`, or
# `//host/share/x`) is a 'root' path on its volume. Recognising one more
# spelling of a path only ever widens what the floor denies or asks about, so
# this is safe even where the spelling means something else -- and without it
# the floor never fired at all on Windows, where every path is spelled that
# way. `C:x`, relative to a drive's current directory, stays 'rel': only the
# server knows where it is. And so that the POSIX meaning of any of these is
# never lost, a token starting with a separator is also read as a plain
# rooted path, exactly as it would be on POSIX.
#
# On top of that, the spellings that reach a volume some other way:
#
# =item an admin share -- `\\host\C$\x`, any host, since the floor cannot tell
#   this machine's names from another's -- is drive C too;
# =item `\\?\` and `\\.\` (either slash) skip Win32's normalisation: before a
#   drive or `UNC\host\share` they are that drive or share, and before a
#   `Volume{…}` GUID or any other device name (`GLOBALROOT\Device\…`) the
#   volume is `*` -- and, since the floor cannot tell how much of a device
#   name the volume takes, every split of it is a reading. Win32 hands such a
#   path over without collapsing its `..`, so the uncollapsed reading is kept
#   too.
#
# :posix reads the token as POSIX does: only `/` separates, and nothing names a
# Windows volume.
my sub read-path(Str:D $token, $home, Bool :$posix --> List:D) {
	my $sep = $posix ?? rx{ '/' } !! SEP;
	my Str $home-base = ($home ~~ Str:D && $home.chars) ?? $home.split(SEP).grep(*.chars).tail !! Str;
	my Str $user-home = $home-base.defined ?? '~' ~ $home-base !! Str;
	my sub sep-at(Int:D $at --> Bool:D) { $token.chars > $at && so $token.substr($at, 1) ~~ $sep }

	# What the token says before its segments are collapsed: one
	# ( kind, volume, rest, collapse ) per reading.
	my @raw;
	if $token eq '~' || ($token.starts-with('~') && sep-at(1)) {
		@raw.push: ('home', '', $token.substr(1), True);
	}
	# `~user` for THIS user's home, bare or with any path suffix (`~bob/.sadna`).
	elsif $user-home.defined && $token.starts-with($user-home)
			&& ($token.chars == $user-home.chars || sep-at($user-home.chars)) {
		@raw.push: ('home', '', $token.substr($user-home.chars), True);
	}
	elsif $posix {
		@raw.push: ($token.starts-with('/') ?? 'root' !! 'rel', '', $token, True);
	}
	else {
		if $token ~~ / ^ $<drive>=[<[A..Za..z]>] ':' <[\\/]> / {
			@raw.push: ('root', $<drive>.uc ~ ':', $token.substr(2), True);
		}
		elsif $token ~~ / ^ <[\\/]> ** 2 <[?.]> <[\\/]> $<inner>=[.*] $ / {
			@raw.append: device-raw(~$<inner>);
		}
		elsif $token ~~ / ^ <[\\/]> ** 2 $<host>=[<-[\\/]>+] <[\\/]> $<share>=[<-[\\/]>+] $<tail>=[.*] $ / {
			@raw.append: share-raw(~$<host>, ~$<share>, ~$<tail>, True);
		}
		@raw.push: ('root', '', $token, True) if $token.starts-with('/') || $token.starts-with('\\');
		@raw.push: ('rel', '', $token, True) unless @raw;
	}

	my @out;
	for @raw -> ($kind is copy, $volume is copy, $rest, $collapse) {
		# Expand home to absolute BEFORE collapsing, so a `..` that climbs above
		# the home root (`~/../bob`, which the shell resolves back to home) is
		# measured against home's real depth rather than treating home as depth
		# zero.
		my @segs;
		if $kind eq 'home' && $home ~~ Str:D && $home.chars {
			with read-path($home, Str).first(*<kind> eq 'root') -> %h {
				@segs = %h<segs>.list;
				$volume = %h<volume>;
				$kind = 'root';
			}
		}
		for $rest.split($sep) -> $s {
			next if $s eq '';
			if $collapse {
				next if $s eq '.';
				if $s eq '..' { @segs.pop if @segs; next }
			}
			@segs.push: $s;
		}
		@out.push: %( :$kind, :$volume, segs => @segs.List );
	}
	@out.List;
}

# The raw readings of a UNC path: the share itself, and for an admin share
# (`C$`) the drive it is. The share is canonicalised to `\\host\share`,
# case-folded.
my sub share-raw(Str:D $host, Str:D $share, Str:D $tail, Bool:D $collapse --> List:D) {
	my @raw = ('root', '\\\\' ~ $host.fc ~ '\\' ~ $share.fc, $tail, $collapse),;
	@raw.push: ('root', $share.substr(0, 1).uc ~ ':', $tail, $collapse)
		if $share ~~ / ^ <[A..Za..z]> '$' $ /;
	@raw.List;
}

# The raw readings of what follows a `\\?\` or `\\.\` prefix: see read-path.
# Each one twice, collapsed and not.
my sub device-raw(Str:D $inner --> List:D) {
	my @raw;
	for (True, False) -> $collapse {
		if $inner ~~ / ^ $<drive>=[<[A..Za..z]>] ':' [ <[\\/]> | $ ] / {
			@raw.push: ('root', $<drive>.uc ~ ':', $inner.substr(2), $collapse);
		}
		elsif $inner ~~ / ^ :i 'UNC' <[\\/]> $<host>=[<-[\\/]>+] <[\\/]> $<share>=[<-[\\/]>+] $<tail>=[.*] $ / {
			@raw.append: share-raw(~$<host>, ~$<share>, ~$<tail>, $collapse);
		}
		elsif $inner ~~ / ^ :i 'Volume{' <-[\\/]>* $<tail>=[ <[\\/]> .* ]? $ / {
			@raw.push: ('root', '*', ~($<tail> // ''), $collapse);
		}
		else {
			# GLOBALROOT\Device\HarddiskVolume3\x, a pipe, a raw device: the
			# volume is some prefix of these segments, and every one is tried.
			my @parts = $inner.split(SEP).grep(*.chars);
			@raw.push: ('root', '*', @parts.skip($_).join('\\'), $collapse) for 1 .. @parts.elems;
		}
	}
	@raw.List;
}

my sub normalize-dir($dir) {
	return Str unless $dir ~~ Str:D && $dir.chars;
	$dir eq '/' ?? '/' !! $dir.subst(/ '/'+ $ /, '');
}
