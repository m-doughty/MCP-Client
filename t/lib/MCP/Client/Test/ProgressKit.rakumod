=begin pod

=head1 NAME

MCP::Client::Test::ProgressKit - a toolkit whose tools report progress

=head1 DESCRIPTION

An C<MCP::Server::Toolkit> for testing the progress path end to end: plug it
into a real C<MCP::Server>, put a client (or an agent) in front of that, and the
tools report progress the way a long-running tool really does — through
C<$*MCP-REQUEST-CONTEXT.progress>, which quotes back the C<progressToken> the
client attached to the request and stays quiet when there was none.

It is deliberately separate from L<MCP::Client::Test::TestKit>, which a great
many tests compare answers against: adding progress to C<echo> would make every
one of those tests carry a notification they never asked about.

=head2 What is in it

=item C<march> — reports progress C<steps> times (C<total> and a C<message> on
      each), then answers with how many of those reports were actually
      delivered. C<ms> sleeps that long between steps, for a caller that wants
      to observe progress before the call answers.
=item C<silent> — answers without reporting anything at all: the well-behaved
      server that was given a token and had nothing to say, which must leave a
      progress hook cold.
=item C<stray> — emits a C<notifications/progress> under a token nobody minted,
      which is what a late report from a finished call looks like from the
      client's side. A client must drop it rather than attribute it to whatever
      call happens to be in flight.

Every handler counts its invocations (C<count-of('march')>), which is how a
test proves a call really ran rather than that its answer looked plausible.

=head1 EXAMPLES

=begin code :lang<raku>
use MCP::Server;
use MCP::Client;
use MCP::Client::Test::InProcessTransport;
use MCP::Client::Test::ProgressKit;

my $server = MCP::Server.new(:name<progress>, :version<1.0.0>);
$server.plug(MCP::Client::Test::ProgressKit.new);

my @seen;
my $client = MCP::Client.new(
	transport   => MCP::Client::Test::InProcessTransport.new(:$server),
	on-progress => -> %p { @seen.push(%p) },
);

$client.execute-tool-calls([
	%( id => 'call_1', function => %( name => 'march', arguments => %( steps => 3 ) ) ),
]);

say @seen.map({ $_<progress> });          # (1 2 3)
say @seen.map({ $_<tool-call-id> }).unique;   # (call_1)
=end code

=end pod

use MCP::Server::Protocol;
use MCP::Server::Toolkit;

unit class MCP::Client::Test::ProgressKit does MCP::Server::Toolkit;

#| Steps C<march> takes when the call names no C<steps> of its own.
has Int:D $.steps = 3;

#| Milliseconds C<march> spends on each step when the call names no C<ms>.
#| Zero by default: a test that does not need the delay should not pay for it.
has Real:D $.step-ms = 0;

#| The token C<stray> quotes. Deliberately not one a client could have minted.
has Str:D $.stray-token = 'not-a-token-anybody-minted';

has Lock $!lock .= new;
has %!counts;

#| How many times a named handler has run.
method count-of(Str:D $name --> Int:D) {
	$!lock.protect: { %!counts{$name} // 0 }
}

#| Every counter, for a test that wants to assert on the lot.
method counts(--> Hash:D) {
	$!lock.protect: { %!counts.Hash }
}

method !bump(Str:D $name --> Nil) {
	$!lock.protect: { %!counts{$name} = (%!counts{$name} // 0) + 1 };
}

method register($registrar) {
	$registrar.tool: 'march',
		description => 'Work through some steps, reporting progress as it goes',
		params => {
			steps => { type => 'integer', description => 'How many steps to take' },
			ms    => { type => 'integer', description => 'Milliseconds per step' },
			label => { type => 'string', description => 'What to call each step' },
		},
		handler => -> :%args {
			self!bump('march');

			my $steps = %args<steps> ~~ Real:D ?? %args<steps>.Int !! $!steps;
			my $ms    = %args<ms> ~~ Real:D ?? %args<ms>.Real !! $!step-ms;
			my $label = (%args<label> // 'step').Str;

			my $sent = 0;
			for 1 .. $steps -> $i {
				sleep $ms / 1000 if $ms > 0;
				# Straight through the request context: the toolkit has no handle
				# on the server, and the context is the thing that knows whether
				# this request asked for progress at all. Nothing is written to
				# $*ERR, which matters when the server is running inside a test
				# harness reading TAP off stdout.
				$sent++ if $*MCP-REQUEST-CONTEXT.progress(
					$i, total => $steps, message => "$label $i",
				);
			}

			"$label done: $sent of $steps";
		};

	$registrar.tool: 'silent',
		description => 'Answer without reporting any progress',
		handler => -> :%args {
			self!bump('silent');
			'nothing to report';
		};

	$registrar.tool: 'stray',
		description => 'Report progress under a token the client never minted',
		handler => -> :%args {
			self!bump('stray');

			with $*MCP-REQUEST-CONTEXT {
				.emit-notification(notification('notifications/progress', {
					progressToken => $!stray-token,
					progress      => 1,
					total         => 1,
					message       => 'for somebody else entirely',
				}));
			}

			'reported to nobody';
		};
}
