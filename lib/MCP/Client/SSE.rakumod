=begin pod

=head1 NAME

MCP::Client::SSE - an incremental Server-Sent Events parser

=head1 DESCRIPTION

A 2026-07-28 MCP server may answer a Streamable HTTP request with an SSE
stream: notifications first, then the response that ends the request. The
bytes of that stream arrive in whatever sizes the network felt like, and none
of those sizes have anything to do with where events end. A parser that treats
each chunk as a unit will eventually try to decode half a JSON object and take
the whole connection down with it.

This class is the fix, and it is deliberately standalone: feed it bytes or
text as they arrive, tap C<events> for whole events. It holds an incomplete
trailing event back until the rest of it turns up, and it decodes UTF-8
incrementally, so a chunk boundary landing in the middle of a multi-byte
character is a non-event rather than an exception.

=head2 What counts as an event

Per the SSE specification:

=item Events are separated by a blank line — C<\n\n>, C<\r\n\r\n> or C<\r\r>.
=item A line beginning with C<:> is a comment. Keepalives (C<: ping>) are
      comments, and are skipped.
=item C<data:> lines accumulate; multiple C<data:> lines in one event are
      joined with a newline, which is how a server sends multi-line JSON.
=item One optional space after the field's colon is part of the syntax, not
      the value, and is stripped.
=item C<event:> names the event type (C<message> when unnamed), C<id:> sets
      the last event id, C<retry:> a reconnection delay in milliseconds.
      Unknown fields are ignored.
=item An event carrying no C<data> is not dispatched.

Emitted events are hashes: C<type>, C<data>, and C<id>/C<retry> when the event
set them.

=head2 Closing

C<close> ends the C<events> supply. By default it also parses whatever is left
in the buffer, because the last event of an HTTP response body is routinely
sent without its trailing blank line, and for MCP that last event is the one
carrying the response — dropping it would hang the request that is waiting for
it. Pass C<:!flush> for the strict reading, where an unterminated trailing
event is discarded.

=head1 EXAMPLES

Parsing a response body as it arrives:

=begin code :lang<raku>
use MCP::Client::SSE;
use JSON::Fast;

my $sse = MCP::Client::SSE.new;

# Tap before feeding: the supply is live, and events are dropped, not
# buffered, while nothing is listening.
$sse.events.tap: -> %event {
	my %msg = from-json(%event<data>);
	%msg<id>:exists ?? $correlator.resolve(%msg<id>, %msg<result>)
	                !! $notifications.emit(%msg);
};

react {
	whenever $response.body-byte-stream -> $bytes { $sse.feed($bytes) }
	whenever $response.body-byte-stream.done { $sse.close }
}
=end code

Chunk boundaries are irrelevant — these two feeds produce exactly one event:

=begin code :lang<raku>
my $sse = MCP::Client::SSE.new;
my @seen;
$sse.events.tap: { @seen.push($_) };

$sse.feed(qq:to/CHUNK/.chomp);
    : keepalive
    event: message
    data: {"jsonrpc":"2.0","id":1,"res
    CHUNK
$sse.feed(qq:to/CHUNK/);
    ult":{"ok":true}}

    CHUNK

say @seen.elems;        # 1
say @seen[0]<type>;     # message
say @seen[0]<data>;     # {"jsonrpc":"2.0","id":1,"result":{"ok":true}}
=end code

=end pod

unit class MCP::Client::SSE;

has Supplier $!supplier .= new;
has Lock     $!lock .= new;
has Str      $!buffer = '';
has Str      $!last-event-id = '';
has Bool     $!closed = False;
has          $!decoder;

# A blank line ends an event. All three line terminators the specification
# allows are accepted, including a lone CR, which no sane server emits and one
# insane server certainly will.
my regex event-boundary { \r\n \r\n | \n \n | \r \r }
my regex line-boundary  { \r\n | \n | \r }

#| The live Supply of parsed events. Tap it before feeding anything: a live
#| supply drops what it emits while nobody is listening.
method events(--> Supply:D) {
	$!supplier.Supply;
}

#| Feed the parser more of the stream. Bytes are decoded incrementally, so a
#| chunk may end anywhere at all — including halfway through a multi-byte
#| character. Any events completed by this chunk are emitted before it returns.
#|
#| Feeding after C<close> is a no-op rather than an error: a stream that ends
#| while a chunk is still in flight is ordinary.
proto method feed($data --> Nil) {*}
multi method feed(Blob:D $bytes --> Nil) { self!ingest($bytes) }
multi method feed(Str:D $text --> Nil)   { self!ingest($text) }

#| End the stream, emitting the held-back tail as a final event unless
#| C<:!flush>. Idempotent.
method close(Bool:D :$flush = True --> Nil) {
	my @events;
	my Bool $first = False;

	$!lock.protect: {
		unless $!closed {
			$!closed = True;
			$first = True;
			if $flush {
				# Anything the decoder is still holding is an incomplete
				# character at the very end of the stream; there is nothing
				# more coming to complete it, so it is dropped rather than
				# allowed to throw here.
				with $!decoder {
					my $rest = try .consume-all-chars;
					$!buffer ~= $rest // '';
				}
				@events = self!parse-blocks(($!buffer,));
			}
			$!buffer = '';
			$!decoder = Nil;
		}
	}

	self!emit(@events);
	$!supplier.done if $first;
	Nil;
}

#| Quit the stream with an exception — what a transport does when the
#| connection dies mid-response, so that everything tapping the events knows
#| the stream ended badly rather than simply ending. Idempotent.
method quit(Exception:D $error --> Nil) {
	my Bool $first = False;
	$!lock.protect: {
		unless $!closed {
			$!closed = True;
			$first = True;
			$!buffer = '';
			$!decoder = Nil;
		}
	}
	$!supplier.quit($error) if $first;
	Nil;
}

#| True once the stream has been closed or quit.
method closed(--> Bool:D) {
	$!lock.protect: { $!closed }
}

#| The id of the most recent event that carried one ('' if none has). This is
#| the value a reconnecting client sends as Last-Event-ID.
method last-event-id(--> Str:D) {
	$!lock.protect: { $!last-event-id }
}

#| The unterminated tail currently held back, for diagnostics.
method pending-tail(--> Str:D) {
	$!lock.protect: { $!buffer }
}

# Buffer, split, hold the tail back, parse what is whole. Parsing happens under
# the lock (it touches the buffer and the last-event-id); emitting happens
# outside it, so a tap that turns round and calls back in cannot deadlock.
method !ingest($data --> Nil) {
	my @events;
	$!lock.protect: {
		unless $!closed {
			$!buffer ~= $data ~~ Blob ?? self!decode($data) !! $data;
			my @blocks = $!buffer.split(&event-boundary);
			$!buffer = @blocks.pop // '';
			@events = self!parse-blocks(@blocks);
		}
	}
	self!emit(@events);
	Nil;
}

method !decode(Blob:D $bytes --> Str:D) {
	without $!decoder {
		# :translate-nl(False) matters: the parser is responsible for line
		# endings, and a decoder that quietly turned CRLF into LF would hide
		# them from it.
		$!decoder = Encoding::Registry.find('utf-8').decoder(:translate-nl(False));
	}
	$!decoder.add-bytes($bytes);
	$!decoder.consume-available-chars;
}

method !parse-blocks(@blocks --> List:D) {
	my @events;
	for @blocks -> $block {
		my %event = self!parse-block($block);
		@events.push(%event) if %event.elems;
	}
	@events.List;
}

# One event block to an event hash, or an empty hash when the block dispatches
# nothing (a keepalive, a run of blank lines, an event with no data).
method !parse-block(Str:D $block --> Hash) {
	my Str $type = '';
	my Str @data;
	my Str $id;
	my Int $retry;

	for $block.split(&line-boundary) -> $line {
		next unless $line.chars;
		next if $line.starts-with(':');

		my $colon = $line.index(':');
		my ($field, $value) = $colon.defined
			?? ($line.substr(0, $colon), $line.substr($colon + 1))
			!! ($line, '');
		$value = $value.substr(1) if $value.starts-with(' ');

		given $field {
			when 'event' { $type = $value }
			when 'data'  { @data.push($value) }
			when 'id'    {
				# The specification forbids a NUL in an event id outright.
				$id = $value unless $value.contains("\0");
			}
			when 'retry' { $retry = $value.Int if $value ~~ /^ \d+ $/ }
			# Any other field name is ignored, as the specification requires:
			# a server is allowed to invent fields and an old client must not
			# choke on them.
			default      { }
		}
	}

	$!last-event-id = $id if $id.defined;
	return {} unless @data.elems;

	my %event = type => ($type.chars ?? $type !! 'message'), data => @data.join("\n");
	%event<id> = $id if $id.defined;
	%event<retry> = $retry if $retry.defined;
	%event;
}

method !emit(@events --> Nil) {
	$!supplier.emit($_) for @events;
	Nil;
}
