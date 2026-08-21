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
#| parameterise the target checks (pass the same values to C<floor-checks>).
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
our sub floor-checks(:$home, :$sadna-home --> Hash:D) is export {
	my $home-dir  = normalize-dir($home);
	my $sadna-dir = normalize-dir($sadna-home);

	{
		'rm-destroy-root'         => -> %cmd { rm-destroy(%cmd, $home-dir, :root) },
		'rm-destroy-unverifiable' => -> %cmd { rm-destroy(%cmd, $home-dir, :unverifiable) },
		'git-danger'              => -> %cmd { git-danger(%cmd) },
		'writes-config'           => -> %cmd { writes-config(%cmd, $home-dir, $sadna-dir) },
		'writes-sensitive'        => -> %cmd { writes-sensitive(%cmd) },
	}
}

# === Checks ===

# Recursive rm at a catastrophic (root, :root) or an unreadable (:unverifiable)
# target. 'yes' fires the rule, 'no' passes it by, 'unknown' fails closed.
my sub rm-destroy(%cmd, $home, :$root, :$unverifiable --> Str:D) {
	return 'unknown' unless %cmd<program>.defined;
	return 'no' unless %cmd<program>.fc eq 'rm';   # fold: catch `RM` on a case-insensitive host
	my @tokens = %cmd<tokens>.list;
	return 'no' unless is-recursive(@tokens);

	if $root {
		# A literal target that is the filesystem root or the home directory.
		return 'yes' if @tokens.grep({ !.starts-with('-') && catastrophic-target($_, $home) });
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
my sub writes-config(%cmd, $home, $sadna --> Str:D) {
	return 'no' unless $sadna.chars;
	for candidate-paths(%cmd) -> $raw {
		# Resolve tilde and collapse `.`/`..`/`//` first, so an obfuscated
		# `~/x/../.sadna/config` cannot slip past `path-under` (which refuses to
		# reason about a `..`). A path we cannot resolve to an absolute form
		# (purely relative, or an unreadable token) is left to the OS sandbox
		# (module 8 phase 6 makes $SADNA_HOME read-only) rather than over-denied.
		my $abs = resolve-abs($raw, $home);
		next without $abs;
		# Fold: local filesystem, case-insensitive on macOS/Windows (see
		# catastrophic-target). `.fc` both sides — pure lexical ASCII compare.
		return 'yes' if path-under($sadna.fc, $abs.fc) eq 'yes';
	}
	'no';
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
# `/x/..`, `~/.`, `~//` and the expanded `$home` are all caught, not just the
# bare spellings.
my sub catastrophic-target(Str:D $token, $home --> Bool:D) {
	my %n = normalize-path($token, $home);
	return True if %n<kind> eq 'home' && !%n<segs>;   # the home directory itself
	return False unless %n<kind> eq 'root';
	return True unless %n<segs>;                       # the filesystem root
	if $home.defined && $home.chars && $home.starts-with('/') {
		# Fold case: the shell floor's targets are the LOCAL filesystem, which on
		# macOS/Windows is case-insensitive, so `/Users/Bob` IS home. Over-deny on
		# a case-sensitive host is the safe direction.
		return True if %n<segs>.map(*.fc).List eqv normalize-path($home, $home)<segs>.map(*.fc).List;
	}
	False;
}

# Take a path apart into C<< { kind, segs } >>: kind is 'root' (absolute), 'home'
# (tilde- or ~user-rooted at this user's home), or 'rel'. Segments have `.`,
# empty and `..` collapsed. Lexical only; the collapse is safe here because it
# only ever widens what counts as catastrophic (the deny direction).
my sub normalize-path(Str:D $token, $home --> Hash:D) {
	my $home-base = ($home ~~ Str:D && $home.chars) ?? $home.split('/').grep(*.chars).tail !! Str;

	my ($kind, $rest);
	my $user-home = $home-base.defined ?? '~' ~ $home-base !! Str;
	if $token eq '~' { $kind = 'home'; $rest = '' }
	elsif $token.starts-with('~/') { $kind = 'home'; $rest = $token.substr(1) }
	# `~user` for THIS user's home, bare or with any path suffix (`~bob/.sadna`).
	elsif $user-home.defined && ($token eq $user-home || $token.starts-with($user-home ~ '/')) {
		$kind = 'home'; $rest = $token.substr($user-home.chars);
	}
	elsif $token.starts-with('/') { $kind = 'root'; $rest = $token }
	else { $kind = 'rel'; $rest = $token }

	# Expand home to absolute BEFORE collapsing, so a `..` that climbs above the
	# home root (`~/../bob`, which the shell resolves back to home) is measured
	# against home's real depth rather than treating home as depth zero.
	my @segs;
	if $kind eq 'home' && $home ~~ Str:D && $home.chars && $home.starts-with('/') {
		@segs = $home.split('/').grep({ $_ ne '' && $_ ne '.' });
		$kind = 'root';
	}
	for $rest.split('/') -> $s {
		next if $s eq '' || $s eq '.';
		if $s eq '..' { @segs.pop if @segs; next }
		@segs.push: $s;
	}
	%( :$kind, segs => @segs.List );
}

# A candidate path resolved to a clean absolute string, or the Str type object
# when it cannot be (a relative path with no root to measure from).
my sub resolve-abs(Str:D $path, $home --> Str) {
	# normalize-path already folds a tilde with an absolute home into a 'root'
	# path; 'home' only survives when there is no absolute home to expand against.
	my %n = normalize-path($path, $home);
	return '/' ~ %n<segs>.list.join('/') if %n<kind> eq 'root';
	Str;   # purely relative, or an unexpandable home — leave it to the sandbox
}

my sub normalize-dir($dir) {
	return Str unless $dir ~~ Str:D && $dir.chars;
	$dir eq '/' ?? '/' !! $dir.subst(/ '/'+ $ /, '');
}
