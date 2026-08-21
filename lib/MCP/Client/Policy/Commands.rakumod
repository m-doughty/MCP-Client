=begin pod

=head1 NAME

MCP::Client::Policy::Commands - what a shell tool call would actually run

=head1 DESCRIPTION

A shell tool takes an argv vector and C<exec>s it directly — no shell — so a
rule that matches C<command =E<gt> 'git'> can trust that the program really is
git. The one hole is a model that runs the shell itself:
C<< ['bash', '-c', 'git status && rm -rf /'] >> is a single C<bash> to the
argv, but two commands to the machine, and the second is not git.

This module closes that hole. Given the literal argv of a call it returns the
list of commands the call B<effectively> runs: it strips fixed wrappers
(C<env>, C<timeout>, C<nice> …), and when the program is a shell run with
C<-c> it lexes the payload — respecting quotes, operators, redirections,
command substitutions and parameter expansion — and returns each simple command
inside it, recursing through nested shells and substitutions.

It never executes anything and never resolves an expansion. Its whole job is to
be B<safe>: everything it cannot read for certain — a C<$VAR>, a C<$(…)>, a
glob, an unbalanced quote — is reported as unreadable rather than guessed, so a
rule that would allow on a guess never fires and a rule that would deny on doubt
always does. Stripping a wrapper can only ever expose the real program or
mis-name it (which falls through to C<ask>); it can never hide a dangerous one.

=head2 The shape it returns

Each effective command is a hash, the same shape C<evaluate> matches against:

=item C<program> — the normalised program basename, or the C<Str> type object
      when the program cannot be identified (an expansion or glob in argv[0]).
=item C<tokens> — the literal argv tokens the engine can read, in order, up to
      the first one it cannot.
=item C<sealed> — whether C<tokens> is the whole argv tail (C<True>) or stops at
      an unreadable token (C<False>). An C<args> prefix that would read past an
      unsealed tail is C<unknown>, not a miss.
=item C<redirect-targets> — the literal targets of any redirections in the
      command (C<E<gt> file>), for rules about what a command may write to.

=end pod

unit module MCP::Client::Policy::Commands;

# The interpreters whose argv hides a command until a `-c` payload is lexed.
my constant SHELL-INTERPRETERS = <sh bash zsh dash ksh mksh ash>.Set;

#| The program name a command rule matches against: the last C<'/'>- or
#| C<'\'>-separated segment, with one recognised executable extension stripped
#| so a rule written C<git> matches C<git.exe> and C<C:\bin\git.EXE> alike.
our sub command-basename(Str:D $program --> Str:D) is export {
	my $last = $program.split(/<[\/\\]>/).grep(*.chars).tail // $program;
	my $stripped = $last.subst(/:i '.' [exe|bat|cmd|com] $ /, '');
	$stripped.chars ?? $stripped !! $last;
}

# Prefixes that run another command unchanged: stripping them exposes the real
# program. `exec`/`command`/`builtin`/`coproc` are shell builtins that run the
# command that follows; `busybox` runs the applet that follows (`busybox sh -c …`
# then falls through to the interpreter path). Deliberately excludes runners
# (xargs, npx, docker, ssh, sudo, find -exec, watch, env -S) — those transform
# or relocate execution and must be named by an explicit rule.
my constant WRAPPERS =
	<env timeout time nice nohup stdbuf ionice setsid exec command builtin coproc busybox>.Set;

# Shell control/negation keywords that prefix a command (`if rm`, `! rm`,
# `while rm`): dropped bare, exposing the command they guard. `[`/`[[`/`test`
# are NOT here — they are commands in their own right, not prefixes.
my constant KEYWORDS = set('if', 'elif', 'while', 'until', 'then', 'do', 'else', '!');

# How deep nested shells / substitutions may go before we stop trying and call
# it unreadable. Pathological `sh -c 'sh -c "..."'` towers end here.
my constant MAX-DEPTH = 8;

# An unreadable command: the engine could not identify what runs. Deny/ask fire
# on it, allow never does.
my sub unknown-command(@redirects = () --> Hash:D) {
	%( program => Str, tokens => ().List, sealed => False, redirect-targets => @redirects.List );
}

#| Decompose a literal argv into the commands it effectively runs. C<$sealed> is
#| whether the argv is fully readable (a caller that could not read every token
#| passes C<False>, and the unreadable tail is treated as such).
our sub decompose-argv(@argv, Bool :$sealed = True, Int :$depth = 0 --> List:D) is export {
	return (unknown-command(),).List if $depth >= MAX-DEPTH;

	# The argv is a run of literal words; an unsealed tail becomes one trailing
	# unreadable word, so the shared machinery computes `sealed` uniformly.
	my @words = @argv.map({ %( literal => True, text => ($_ // '').Str ) }).Array;
	@words.push({ literal => False, text => '' }) unless $sealed;

	words-to-effective(@words, (), (), $depth);
}

# The shared core: one simple command as a word list (each word literal or not),
# its redirect targets, and the command-substitution payloads found in it.
# Returns every effective command it stands for — itself, whatever a `-c`
# payload expands to, and whatever its substitutions run.
my sub words-to-effective(@words-in, @redirects, @subs, Int $depth --> List:D) {
	return (unknown-command(@redirects),).List if $depth >= MAX-DEPTH;

	my %stripped = strip-wrappers(@words-in);
	return (unknown-command(@redirects),).List unless %stripped<ok>;
	my @words = %stripped<words>.list;
	return (unknown-command(@redirects),).List unless @words;

	my @out;

	my %first = @words[0];
	if !%first<literal> {
		# The program itself is an expansion or a glob: unidentifiable.
		@out.push: unknown-command(@redirects);
	}
	else {
		my $program = command-basename(%first<text>);

		# Structural lookups fold case: on a case-insensitive filesystem `BASH`
		# and `EVAL` are the real programs, and folding here only ever leads to
		# MORE decomposition (the payload gets lexed, the wrapper stripped), i.e.
		# more scrutiny — never less. Rule matching stays case-exact for allow.
		if $program.fc eq 'eval' {
			@out.append: eval-effective(@words, @redirects, $depth);
		}
		elsif SHELL-INTERPRETERS{$program.fc} {
			@out.append: interpreter-effective($program, @words, @redirects, $depth);
		}
		else {
			@out.push: plain-effective($program, @words, @redirects);
		}
	}

	# Whatever the command line was, its command substitutions run too. A
	# payload that will not lex is unreadable, NOT nothing: dropping it would let
	# a command hidden in a substitution vanish and the benign outer command
	# stand alone, so an empty result becomes one unknown command (fail closed,
	# exactly as the interpreter path does).
	for @subs -> $payload {
		my @sub = lex-and-decompose($payload, $depth + 1);
		@out.append: @sub ?? @sub.List !! (unknown-command(),).List;
	}

	@out.List;
}

# A non-shell command: program plus the literal argv tail up to the first token
# the engine cannot read.
my sub plain-effective(Str:D $program, @words, @redirects --> Hash:D) {
	my @tokens;
	my $sealed = True;
	for @words[1..*] -> %w {
		if %w<literal> { @tokens.push: %w<text> }
		else { $sealed = False; last }
	}
	%( :$program, tokens => @tokens.List, :$sealed, redirect-targets => @redirects.List );
}

# `eval` joins its arguments into one string and runs it as shell code — the
# same hole as `sh -c`. Lex the joined literal arguments; if any argument is
# unreadable the string cannot be trusted, so the command is unknown.
my sub eval-effective(@words, @redirects, Int $depth --> List:D) {
	my @rest = @words[1 .. *];
	return (unknown-command(@redirects),).List if @rest.grep({ !$_<literal> });
	return (plain-effective('eval', @words, @redirects),).List unless @rest;

	my $code = @rest.map(*<text>).join(' ');
	my @inner = lex-and-decompose($code, $depth + 1);
	@inner ?? @inner.List !! (unknown-command(@redirects),).List;
}

# A shell interpreter: if it is handed a `-c` payload we can read, the commands
# are inside it; otherwise the interpreter itself is the command (a bare `bash`
# reads stdin or a script — arbitrary code, which the floor asks about).
my sub interpreter-effective(Str:D $program, @words, @redirects, Int $depth --> List:D) {
	my $payload = dash-c-payload(@words);

	# No -c at all: the interpreter runs a script/stdin. Report it as itself.
	return (plain-effective($program, @words, @redirects),).List
		if $payload === Any;

	# A -c whose payload we cannot read (an expansion): unknown.
	return (unknown-command(@redirects),).List unless $payload ~~ Str:D;

	my @inner = lex-and-decompose($payload, $depth + 1);
	# A payload that would not lex is unreadable, not empty.
	@inner ?? @inner.List !! (unknown-command(@redirects),).List;
}

# The payload string of a `-c` option in a word list, or `Any` when there is no
# `-c`, or a non-Str sentinel when the `-c` is there but its payload cannot be
# read. Handles `-c`, clustered short options ending in c (`-lc`), and `--`.
my sub dash-c-payload(@words) {
	my $i = 1;
	while $i < @words.elems {
		my %w = @words[$i];
		unless %w<literal> {
			# An unreadable word in option position: cannot tell if it is -c.
			return %( unreadable => True );
		}
		my $t = %w<text>;
		last unless $t.starts-with('-') && $t ne '-';
		return %( unreadable => True ) if $t eq '--';   # end of options, no -c seen as such

		# A single-dash cluster (or exactly -c). A cluster ending in c takes the
		# next word as the command string; -c likewise.
		if !$t.starts-with('--') && $t.substr(1).contains('c') {
			my $rest = $t.substr(1);
			# If c is not the last letter, bash treats the remainder as the
			# payload glued on (e.g. -cecho). Rare; treat the glued form as the
			# payload when non-empty, else the next word.
			my $after-c = $rest.substr($rest.index('c') + 1);
			return $after-c if $after-c.chars;
			my %next = @words[$i + 1] // Nil;
			return Any without %next;
			return %( unreadable => True ) unless %next<literal>;
			return %next<text>;
		}
		$i++;
	}
	Any;
}

# Lex a shell string and decompose every simple command in it. A lex failure
# yields nothing, which the caller reads as unreadable.
my sub lex-and-decompose(Str:D $payload, Int $depth --> List:D) {
	return (unknown-command(),).List if $depth >= MAX-DEPTH;
	my %lexed = lex-shell($payload);
	return ().List unless %lexed<ok>;

	my @out;
	for %lexed<commands>.list -> %cmd {
		@out.append: words-to-effective(%cmd<words>.list, %cmd<redirects>.list, %cmd<subs>.list, $depth);
	}
	@out.List;
}

# === Wrappers ===

# Strip leading wrapper commands, exposing the program they run. Returns
# C<< { ok, words } >>. `ok` is False only for a wrapper form we refuse to see
# through (`env -S`, which splits a string into a command the way `sh -c` does,
# and so would let a rule match the wrapper while the real command hides in the
# string).
my sub strip-wrappers(@words-in --> Hash:D) {
	my @words = @words-in.Array;

	loop {
		return %( ok => True, words => @words.List ) unless @words && @words[0]<literal>;

		# A leading control keyword (`if`, `!`, `while` …) guards a command:
		# drop it bare and look again at what it guarded.
		my $head = @words[0]<text>;
		if KEYWORDS{$head.fc} || KEYWORDS{command-basename($head).fc} {
			@words = @words[1 .. *].Array;
			next;
		}

		my $prog = command-basename(@words[0]<text>);
		return %( ok => True, words => @words.List ) unless WRAPPERS{$prog.fc};

		my $i = 1;
		while $i < @words.elems && @words[$i]<literal> {
			my $t = @words[$i]<text>;
			if $prog.fc eq 'env' {
				# `env -S "cmd string"` hides a command inside a string, the way
				# `sh -c` does: refuse to see through it, so a rule cannot match
				# `env` while the real command escapes unchecked.
				return %( ok => False, words => ().List ) if $t eq '-S' || $t eq '--split-string'
					|| ($t.starts-with('-') && !$t.starts-with('--') && $t.contains('S'));
				# consume an option or a NAME=value assignment; stop at the command
				last unless $t.starts-with('-') || ($t.contains('=') && $t !~~ /^ '=' /);
				$i++;
				next;
			}
			# Other wrappers: consume their options and simple numeric/duration
			# arguments (timeout's duration, nice -n N). A word we do not
			# recognise as belonging to the wrapper is the wrapped program.
			if $t.starts-with('-') && $t ne '-' {
				$i++;
				# an option that takes a value (-n 10, -k 5): consume the value
				$i++ if $i < @words.elems && @words[$i]<literal>
					&& @words[$i]<text> ~~ /^ <[0..9]>+ <[a..z]>? $/;
				next;
			}
			if $t ~~ /^ <[0..9]>+ <[smhd]>? $/ {
				$i++;   # timeout's duration, ionice's class number
				next;
			}
			last;
		}
		# Strip what we consumed (at least the wrapper name) and look again: a
		# second wrapper behind the first is stripped on the next turn.
		@words = @words[$i .. *].Array;
	}
}

# === The lexer ===

# Take apart a shell string into simple commands. Returns
# C<< { ok, commands => [ { words, redirects, subs } ] } >>. `ok` is False when
# the string cannot be lexed at all (an unterminated quote or substitution),
# which the caller treats as unreadable. Each word is
# C<< { literal, text } >>: `literal` is False once anything the shell would
# expand (a variable, a substitution, a glob, a tilde) has touched it.
our sub lex-shell(Str:D $src --> Hash:D) is export {
	my @chars = $src.comb;
	my $n = @chars.elems;
	my $i = 0;

	my @commands;
	my @words;
	my @redirects;
	my @subs;

	my $buf = '';
	my $literal = True;
	my $has-word = False;
	my $redirect-next = False;   # the next finished word is a redirect target

	my sub flush-word {
		return unless $has-word;
		if $redirect-next {
			@redirects.push($buf) if $literal;
			$redirect-next = False;
		}
		else {
			@words.push({ literal => $literal, text => $buf });
		}
		$buf = ''; $literal = True; $has-word = False;
	}
	my sub flush-command {
		flush-word;
		@commands.push({ words => @words.clone, redirects => @redirects.clone, subs => @subs.clone })
			if @words || @redirects || @subs;
		@words = (); @redirects = (); @subs = ();
	}
	my sub mark-nonliteral { $literal = False; $has-word = True }

	# Scan a balanced run from an opener to its matching closer, honouring
	# quotes; returns (inner, index-after-closer) or (Str, -1) on imbalance.
	my sub balanced($open, $close, $from) {
		# Backticks open and close with the same character, so depth-counting
		# would oscillate and never settle: scan to the next unescaped closer.
		if $open eq $close {
			my $j = $from;
			my $inner = '';
			while $j < $n {
				if @chars[$j] eq '\\' && $j + 1 < $n { $inner ~= @chars[$j + 1]; $j += 2; next }
				return ($inner, $j + 1) if @chars[$j] eq $close;
				$inner ~= @chars[$j]; $j++;
			}
			return (Str, -1);
		}

		my $depth = 1;
		my $j = $from;
		my $inner = '';
		while $j < $n {
			my $c = @chars[$j];
			if $c eq '\\' && $j + 1 < $n { $inner ~= $c ~ @chars[$j + 1]; $j += 2; next }
			if $c eq "'" {
				my $k = $j + 1;
				$inner ~= $c;
				while $k < $n && @chars[$k] ne "'" { $inner ~= @chars[$k]; $k++ }
				return (Str, -1) if $k >= $n;
				$inner ~= "'"; $j = $k + 1; next;
			}
			if $c eq '"' {
				my $k = $j + 1;
				$inner ~= $c;
				while $k < $n {
					if @chars[$k] eq '\\' && $k + 1 < $n { $inner ~= @chars[$k] ~ @chars[$k + 1]; $k += 2; next }
					last if @chars[$k] eq '"';
					$inner ~= @chars[$k]; $k++;
				}
				return (Str, -1) if $k >= $n;
				$inner ~= '"'; $j = $k + 1; next;
			}
			$depth++ if $c eq $open;
			if $c eq $close {
				$depth--;
				return ($inner, $j + 1) if $depth == 0;
			}
			$inner ~= $c; $j++;
		}
		(Str, -1);   # never closed
	}

	while $i < $n {
		my $c = @chars[$i];

		# --- backslash escape ---
		if $c eq '\\' {
			if $i + 1 < $n && @chars[$i + 1] eq "\n" { $i += 2; next }   # line continuation
			if $i + 1 < $n { $buf ~= @chars[$i + 1]; $has-word = True; $i += 2; next }
			$buf ~= $c; $has-word = True; $i++; next;
		}

		# --- single quotes: wholly literal ---
		if $c eq "'" {
			my $k = $i + 1;
			while $k < $n && @chars[$k] ne "'" { $buf ~= @chars[$k]; $k++ }
			return %( ok => False ) if $k >= $n;   # unterminated
			$has-word = True; $i = $k + 1; next;
		}

		# --- double quotes: literal but for $ and ` ---
		if $c eq '"' {
			my $k = $i + 1;
			$has-word = True;
			while $k < $n {
				my $d = @chars[$k];
				if $d eq '\\' && $k + 1 < $n {
					my $e = @chars[$k + 1];
					if $e eq '"' | '\\' | '$' | '`' | "\n" { $buf ~= $e if $e ne "\n"; $k += 2; next }
					$buf ~= $d; $k++; next;
				}
				last if $d eq '"';
				if $d eq '$' {
					my ($consumed, $sub) = scan-expansion(@chars, $k, $n, :balanced(&balanced), :in-dquote);
					return %( ok => False ) if $consumed < 0;
					mark-nonliteral;
					@subs.push($sub) if $sub.defined;
					$k = $consumed; next;
				}
				if $d eq '`' {
					my ($inner, $after) = balanced('`', '`', $k + 1);
					return %( ok => False ) if $after < 0;
					mark-nonliteral;
					@subs.push($inner);
					$k = $after; next;
				}
				$buf ~= $d; $k++;
			}
			return %( ok => False ) if $k >= $n;   # unterminated
			$i = $k + 1; next;
		}

		# --- command substitution / expansion outside quotes ---
		if $c eq '$' {
			# $"…" is a translated double-quoted string: bash still runs the
			# $(…)/`…` inside it, so it must go through the double-quote
			# machinery, not be treated as opaque. Drop the $ (the translation
			# may differ from the literal text, so the word is unreadable) and
			# let the " branch capture the string and its substitutions.
			if $i + 1 < $n && @chars[$i + 1] eq '"' {
				mark-nonliteral;
				$i++;   # re-loop at the opening ", which the " branch handles
				next;
			}
			my ($consumed, $sub) = scan-expansion(@chars, $i, $n, :balanced(&balanced));
			return %( ok => False ) if $consumed < 0;
			mark-nonliteral;
			@subs.push($sub) if $sub.defined;
			$i = $consumed; next;
		}
		if $c eq '`' {
			my ($inner, $after) = balanced('`', '`', $i + 1);
			return %( ok => False ) if $after < 0;
			mark-nonliteral;
			@subs.push($inner);
			$i = $after; next;
		}

		# --- process substitution <( ) >( ) ---
		if ($c eq '<' || $c eq '>') && $i + 1 < $n && @chars[$i + 1] eq '(' {
			my ($inner, $after) = balanced('(', ')', $i + 2);
			return %( ok => False ) if $after < 0;
			mark-nonliteral;
			@subs.push($inner);
			$i = $after; next;
		}

		# --- whitespace: word boundary ---
		if $c eq ' ' | "\t" { flush-word; $i++; next }

		# --- newline: command boundary ---
		if $c eq "\n" | "\r" { flush-command; $i++; next }

		# --- operators ---
		if $c eq ';' { flush-command; $i++; $i++ if $i < $n && @chars[$i] eq ';'; next }   # ; and ;;
		if $c eq '&' {
			if $i + 1 < $n && @chars[$i + 1] eq '&' { flush-command; $i += 2; next }        # &&
			if $i + 1 < $n && @chars[$i + 1] eq '>' {                                       # &> redirect
				flush-word; $redirect-next = True; $has-word = False;
				$i += 2; $i++ if $i < $n && @chars[$i] eq '>'; next;
			}
			flush-command; $i++; next;                                                      # & background
		}
		if $c eq '|' {
			flush-command;
			$i++;
			$i++ if $i < $n && (@chars[$i] eq '|' || @chars[$i] eq '&');                     # || and |&
			next;
		}
		if $c eq '(' { flush-command; $i++; next }   # subshell open: a command boundary
		if $c eq ')' { flush-command; $i++; next }   # subshell close

		# --- redirections ---
		if $c eq '<' || $c eq '>' {
			# A leading fd number (2>) belongs to the redirect, not a word.
			if $has-word && $literal && $buf ~~ /^ <[0..9]>+ $/ {
				$buf = ''; $has-word = False;
			}
			flush-word;
			# consume the redirect operator run (>>, >&, <<, <&, etc.)
			$i++;
			$i++ if $i < $n && (@chars[$i] eq '>' || @chars[$i] eq '<' || @chars[$i] eq '&');
			$redirect-next = True;
			next;
		}

		# --- globbing and brace expansion make the word unreadable ---
		# `rm{,x}` really runs `rm`, `f*o` may be anything: a word the shell
		# would expand cannot be trusted to be the literal text we scanned.
		if $c eq '*' | '?' { mark-nonliteral; $i++; next }
		if $c eq '[' | ']' { mark-nonliteral; $i++; next }
		if $c eq '{' | '}' { mark-nonliteral; $i++; next }
		# `~` is kept LITERAL: tilde expansion is deterministic (→ $HOME), so a
		# token `~`/`~/x` stays readable for the danger-floor's home-target check,
		# and `~/bin/rm` still basenames to `rm`. (Contrast $VAR, which is opaque.)

		# --- ordinary character ---
		$buf ~= $c; $has-word = True; $i++;
	}

	flush-command;
	%( ok => True, commands => @commands.List );
}

# From a `$` at @chars[$from], consume one expansion and return
# (index-after, sub-payload-or-Any). A command substitution `$(…)` yields its
# inner text as the payload to recurse into; every other form yields Any (it is
# just an expansion that makes the word unreadable). Returns (-1, Any) on an
# unbalanced substitution. C<$in-dquote> is set when scanning inside a double
# quote, where `$'` and `$"` are NOT quote introducers (the `$` is a literal
# dollar and the quote is an ordinary character or the closing delimiter).
my sub scan-expansion(@chars, Int $from, Int $n, :&balanced, Bool :$in-dquote = False) {
	my $j = $from + 1;
	return ($from + 1, Any) if $j >= $n;   # a trailing $ is a literal-ish nothing; treat as expansion end

	my $d = @chars[$j];
	if $d eq '(' {
		# $(( )) arithmetic, or $( ) command substitution.
		if $j + 1 < $n && @chars[$j + 1] eq '(' {
			my ($inner, $after) = balanced('(', ')', $j + 2);
			return (-1, Any) if $after < 0;
			# consume the second closing paren of $(( ))
			my $end = $after;
			$end++ if $end < $n && @chars[$end] eq ')';
			return ($end, Any);
		}
		my ($inner, $after) = balanced('(', ')', $j + 1);
		return (-1, Any) if $after < 0;
		return ($after, $inner);
	}
	if $d eq '{' {
		my ($inner, $after) = balanced('{', '}', $j + 1);
		return (-1, Any) if $after < 0;
		return ($after, Any);
	}
	# $'…' ANSI-C quoting, outside double quotes only. The shell decodes the body
	# to one word but does NOT run command substitutions inside it, so treating
	# it as opaque-and-unreadable is both safe and correct. The closing quote is
	# found here (honouring an escaped quote) so the outer lexer does not mistake
	# it for a fresh opening quote and reject valid input. `$"…"` is deliberately
	# NOT handled here — it is a translated double-quoted string whose `$(…)` DO
	# run, so the caller routes it through the double-quote machinery instead.
	if $d eq "'" && !$in-dquote {
		my $k = $j + 1;
		while $k < $n {
			if @chars[$k] eq '\\' && $k + 1 < $n { $k += 2; next }
			last if @chars[$k] eq "'";
			$k++;
		}
		return (-1, Any) if $k >= $n;   # unterminated
		return ($k + 1, Any);
	}
	# $NAME.
	my $k = $j;
	if @chars[$k] ~~ /<[A..Za..z_]>/ {
		$k++ while $k < $n && @chars[$k] ~~ /<[A..Za..z0..9_]>/;
		return ($k, Any);
	}
	# A special single-character parameter: $?, $$, $!, $#, $*, $@, $-, $0-$9.
	return ($k + 1, Any) if @chars[$k] ~~ /<[?!#*@\-0..9] + [$]>/;
	# Anything else — a quote, a space, punctuation — is a literal dollar: only
	# the `$` is consumed, and the following character is scanned normally.
	($j, Any);
}
