unit module CBOR::Simple:auth<zef:japhb>:api<0>:ver<0.0.1>;


enum CBORMajorType is export (
    CBOR_UInt  => 0,
    CBOR_NInt  => 1 +< 5,
    CBOR_BStr  => 2 +< 5,
    CBOR_TStr  => 3 +< 5,
    CBOR_Array => 4 +< 5,
    CBOR_Map   => 5 +< 5,
    CBOR_Tag   => 6 +< 5,
    CBOR_SVal  => 7 +< 5,
);


# Break sentinel
my class Break { }

# Introspection of tagged values
class Tagged {
    has UInt:D $.tag-number is required;
    has Mu     $.value      is required;
    has Str:D  $.desc       =  '';
}

# Parsing exceptions
class X::Malformed is X::AdHoc {}

PROCESS::<$CBOR_SIMPLE_FATAL_ERRORS> = False;


# Encode an arbitrary value to CBOR
multi cbor-encode(Mu $value) is export {
    cbor-encode($value, my $pos = 0)
}

# Encode an arbitrary value to CBOR, specifying a buffer position to begin writing
multi cbor-encode(Mu $value, Int:D $pos is rw, Buf:D $buf = buf8.new) is export {
    my sub write-uint($major-type, $value) {
        if $value <= 23 {
            $buf.write-uint8($pos++, $major-type + $value);
        }
        elsif $value <= 255 {
            $buf.write-uint8($pos++, $major-type + 24);
            $buf.write-uint8($pos++, $value);
        }
        elsif $value <= 65535 {
            $buf.write-uint8($pos++, $major-type + 25);
            $buf.write-uint16($pos, $value, BigEndian);
            $pos += 2;
        }
        elsif $value <= 4294967295 {
            $buf.write-uint8($pos++, $major-type + 26);
            $buf.write-uint32($pos, $value, BigEndian);
            $pos += 4;
        }
        elsif $value <= 18446744073709551615 {
            $buf.write-uint8($pos++, $major-type + 27);
            $buf.write-uint64($pos, $value, BigEndian);
            $pos += 8;
        }
    }

    given $value {
        # Any:U is CBOR null, other Mu:U is CBOR undefined
        when Mu:U {
            $buf.write-uint8($pos++, CBOR_SVal + ($_ ~~ Any ?? 22 !! 23));
        }
        # All other values are defined
        when Bool {
            $buf.write-uint8($pos++, CBOR_SVal + ($_ ?? 21 !! 20));
        }
        when Int {
            if -18446744073709551616 <= $_ <= 18446744073709551615 {
                $_ >= 0 ?? write-uint(CBOR_UInt,   $_)
                        !! write-uint(CBOR_NInt, +^$_);
            }
            # Unsigned BigInt
            elsif $_ >= 0 {
                $buf.write-uint8($pos++, CBOR_Tag + 2);
                my @bytes = .polymod(256 xx *).reverse;
                my $bytes = @bytes.elems;
                write-uint(CBOR_BStr, $bytes);
                $buf.splice($pos, $bytes, @bytes);
                $pos += $bytes;
            }
            # Negative BigInt
            else {
                $buf.write-uint8($pos++, CBOR_Tag + 3);
                my @bytes = (+^$_).polymod(256 xx *).reverse;
                my $bytes = @bytes.elems;
                write-uint(CBOR_BStr, $bytes);
                $buf.splice($pos, $bytes, @bytes);
                $pos += $bytes;
            }
        }
        when Num {
            # XXXX: Doesn't write short NaNs yet

            my num64 $num64 = $_;
            my num32 $num32 = $num64;
            # my num16 $num16 = $num64;

            my $use32 = $num32 == $num64 || $num64.isNaN && do {
                my buf8 $nan .= new;
                $nan.write-num64(0, $num64, BigEndian);
                $nan[4] == $nan[5] == $nan[6] == $nan[7] == 0
            };

            # if $num16 == $num64 {
            #     # XXXX: write-num16 is UNAVAILABLE!
            #     die "Cannot write a 16-bit num";
            #
            #     $buf.write-uint8($pos++, CBOR_SVal + 25);
            #     $buf.write-num16($pos, $num16, BigEndian);
            #
            #     # Canonify NaN sign bit to 0, even on platforms with -NaN
            #     $buf.write-uint8($pos, $buf.read-uint8($pos) +& 0x7F)
            #         if $num16.isNaN;
            #
            #     $pos += 2;
            # }
            if $use32 {
                $buf.write-uint8($pos++, CBOR_SVal + 26);
                $buf.write-num32($pos, $num32, BigEndian);

                # Canonify NaN sign bit to 0, even on platforms with -NaN
                $buf.write-uint8($pos, $buf.read-uint8($pos) +& 0x7F)
                    if $num32.isNaN;

                $pos += 4;
            }
            else {
                $buf.write-uint8($pos++, CBOR_SVal + 27);
                $buf.write-num64($pos, $num64, BigEndian);

                # Canonify NaN sign bit to 0, even on platforms with -NaN
                $buf.write-uint8($pos, $buf.read-uint8($pos) +& 0x7F)
                    if $num64.isNaN;

                $pos += 8;
            }
        }
        when Instant {
            my $num = .to-posix[0].Num;
            my $val = $num.Int == $num ?? $num.Int !! $num;

            $buf.write-uint8($pos++, CBOR_Tag + 1);
            cbor-encode($val, $pos, $buf);
        }
        when DateTime {
            my $num = .Instant.to-posix[0].Num;
            my $val = $num.Int == $num ?? $num.Int !! $num;

            $buf.write-uint8($pos++, CBOR_Tag + 1);
            cbor-encode($val, $pos, $buf);
        }
        when Dateish {
            $buf.write-uint8($pos++, CBOR_Tag);  # + 0
            cbor-encode(.yyyy-mm-dd, $pos, $buf);
        }
        when Real {
            # XXXX: Pretend it's a Num
            cbor-encode(.Num, $pos, $buf);
        }
        when Str {
            my $utf8  = .encode;
            my $bytes = $utf8.bytes;

            write-uint(CBOR_TStr, $bytes);
            $buf.splice($pos, $bytes, $utf8);
            $pos += $bytes;
        }
        when Blob {
            my $bytes = .bytes;

            write-uint(CBOR_BStr, $bytes);
            $buf.splice($pos, $bytes, $_);
            $pos += $bytes;
        }
        # XXXX: Seq/Iterator?
        when Positional {
            write-uint(CBOR_Array, .elems);
            cbor-encode($_, $pos, $buf) for @$_;
        }
        when Associative {
            write-uint(CBOR_Map, .elems);
            my @pairs = .kv.map: -> $k, $v {
                my $kbuf = cbor-encode($k);
                $kbuf => $v
            };
            @pairs.sort(*.key).map: -> (:$key, :$value) {
                my $bytes = $key.bytes;
                $buf.splice($pos, $bytes, $key);
                $pos += $bytes;
                cbor-encode($value, $pos, $buf);
            }
        }
        default {
            my $ex = "Don't know how to encode a {$value.^name}";
            $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
        }
    }

    $buf
}


# Decode the first value from CBOR-encoded data
multi cbor-decode(Blob:D $cbor) is export {
    my $value = cbor-decode($cbor, my $pos = 0);
    if $pos < $cbor.bytes {
        my $ex = X::Malformed.new(:payload("Extra data after decoded value"));
        $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
    }
    $value
}

# Decode the next value from CBOR-encoded data, starting at $pos
multi cbor-decode(Blob:D $cbor, Int:D $pos is rw, Bool:D :$breakable = False) is export {
    my &fail-malformed = -> Str:D $reason {
        my $ex = X::Malformed.new(:payload($reason));
        $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
    }

    CATCH {
        when /^ 'MVMArray: read_buf out of bounds' / {
            fail-malformed "Early end of input";
        }
        default { .rethrow }
    }

    my $initial-byte = $cbor.read-uint8($pos++);
    my $major-type   = $initial-byte +& 0xE0;
    my $argument     = $initial-byte +& 0x1F;

    my &read-uint = -> $allow-indefinite = False {
        if $argument <= 23 {
            $argument
        }
        elsif $argument == 24 {
            $cbor.read-uint8($pos++)
        }
        elsif $argument == 25 {
            my $v = $cbor.read-uint16($pos, BigEndian);
            $pos += 2;
            $v
        }
        elsif $argument == 26 {
            my $v = $cbor.read-uint32($pos, BigEndian);
            $pos += 4;
            $v
        }
        elsif $argument == 27 {
            my $v = $cbor.read-uint64($pos, BigEndian);
            $pos += 8;
            $v
        }
        elsif $argument == 31 {
            $allow-indefinite ?? Whatever
                              !! fail-malformed "Unexpected indefinite argument";
        }
        else {
            fail-malformed "Invalid argument $argument";
        }
    }

    given $major-type {
        when CBOR_UInt {
            read-uint
        }
        when CBOR_NInt {
            +^read-uint
        }
        when CBOR_BStr {
            my $bytes = read-uint(!$breakable);

            # Indefinite length
            if $bytes === Whatever {
                my buf8 $joined .= new;
                while (my $chunk = cbor-decode($cbor, $pos, :breakable)) !=== Break {
                    fail-malformed "Byte string chunk has wrong type"
                        unless $chunk ~~ Buf:D;
                    $joined.append($chunk);
                }
                $joined
            }
            # Definite length
            else {
                fail-malformed "Unreasonably long byte string"
                    if $bytes > 9223372036854775807;

                my $buf = $cbor.subbuf($pos, $bytes);
                fail-malformed "Byte string too short" unless $buf.bytes == $bytes;
                $pos += $bytes;
                $buf
            }
        }
        when CBOR_TStr {
            my $bytes = read-uint(!$breakable);

            # Indefinite length
            if $bytes === Whatever {
                my @chunks;
                while (my $chunk = cbor-decode($cbor, $pos, :breakable)) !=== Break {
                    fail-malformed "Text string chunk has wrong type"
                        unless $chunk ~~ Str:D;
                    @chunks.push($chunk);
                }
                @chunks.join
            }
            # Definite length
            else {
                fail-malformed "Unreasonably long text string"
                    if $bytes > 9223372036854775807;

                my $utf8  = $cbor.subbuf($pos, $bytes);
                fail-malformed "Text string too short" unless $utf8.bytes == $bytes;
                $pos += $bytes;
                $utf8.decode
            }
        }
        when CBOR_Array {
            my $elems = read-uint(True);

            # Indefinite length
            if $elems === Whatever {
                my @array;
                while (my $item = cbor-decode($cbor, $pos, :breakable)) !=== Break {
                    @array.push($item);
                }
                @array
            }
            # Definite length
            else {
                my @ = (^$elems).map: { cbor-decode($cbor, $pos) }
            }
        }
        when CBOR_Map {
            my $elems = read-uint;
            my @pairs = (^$elems).map: {
                my $k = cbor-decode($cbor, $pos);
                my $v = cbor-decode($cbor, $pos);
                $k => $v
            };

            # Contains non-string keys?
            if @pairs.first({.key !~~ Str}) {
                # XXXX: Check for all keys being same type?
                my %{Mu} = @pairs
            }
            else {
                my % = @pairs
            }
        }
        when CBOR_Tag {
            my $tag-number = read-uint;
            given $tag-number {
                when 0 {
                    my $dt = cbor-decode($cbor, $pos);
                    fail-malformed "DateTime tag (0) does not contain a string"
                        unless $dt ~~ Str:D;
                    DateTime.new($dt) // fail-malformed "DateTime string could not be parsed"
                }
                when 1 {
                    my $seconds = cbor-decode($cbor, $pos);
                    fail-malformed "Epoch DateTime tag(1) does not contain a real number"
                        unless $seconds ~~ Real:D;
                    DateTime.new($seconds) // fail-malformed "Epoch DateTime could not be decoded"
                }
                when 2 {
                    my $bytes = cbor-decode($cbor, $pos);
                    fail-malformed "Unsigned BigInt does not contain a byte string"
                        unless $bytes ~~ Buf:D;
                    my $value = 0;
                    $value = $value * 256 + $_ for @$bytes;
                    $value
                }
                when 3 {
                    my $bytes = cbor-decode($cbor, $pos);
                    fail-malformed "Negative BigInt does not contain a byte string"
                        unless $bytes ~~ Buf:D;
                    my $value = 0;
                    $value = $value * 256 + $_ for @$bytes;
                    +^$value
                }

                # XXXX: Handle more special tags

                default {
                    Tagged.new(:$tag-number, :value(cbor-decode($cbor, $pos)))
                }
            }
        }
        when CBOR_SVal {
            my constant %svals = 20 => False, 21 => True, 22 => Any, 23 => Mu;

            if $argument < 20 {
                fail-malformed "Unassigned simple value $argument";
            }
            elsif $argument <= 23 {
                %svals{$argument}
            }
            elsif $argument == 24 {
                my $val  = $cbor.read-uint8($pos++);
                my $fail = $val < 24 ?? "Badly formed" !!
                           $val < 32 ?? "Reserved"     !!
                                        "Unassigned"   ;
                fail-malformed "$fail simple value $val";
            }
            elsif $argument == 25 {
                # XXXX: read-num16 is UNAVAILABLE!
                die "Cannot read a 16-bit num";

                my $v = $cbor.read-num16($pos, BigEndian);
                $pos += 2;
                $v
            }
            elsif $argument == 26 {
                my $v = $cbor.read-num32($pos, BigEndian);
                $pos += 4;
                $v
            }
            elsif $argument == 27 {
                my $v = $cbor.read-num64($pos, BigEndian);
                $pos += 8;
                $v
            }
            elsif $argument == 31 {
                $breakable ?? Break
                           !! fail-malformed "Unexpected break signal";
            }
            else {
                # XXXX: Not handling indefinite length stop code yet
                fail-malformed "Badly formed simple value $argument";
            }
        }
    }
}


# Convert a CBOR-encoded value to human diagnostic form
multi cbor-diagnostic(Blob:D $cbor) is export {
    cbor-diagnostic($cbor, my $pos = 0)
}

# Convert a CBOR-encoded value to human diagnostic form, starting at $pos
multi cbor-diagnostic(Blob:D $cbor, Int:D $pos is rw) is export {
    my $initial-byte = $cbor.read-uint8($pos++);
    my $major-type   = $initial-byte +& 0xE0;
    my $val          = $initial-byte +& 0x1F;

    given $major-type {
        when CBOR_UInt {
            ...
        }
        when CBOR_NInt {
            ...
        }
        when CBOR_BStr {
            ...
        }
        when CBOR_TStr {
            ...
        }
        when CBOR_Array {
            ...
        }
        when CBOR_Map {
            ...
        }
        when CBOR_Tag {
            ...
        }
        when CBOR_SVal {
            ...
        }
    }
}


=begin pod

=head1 NAME

CBOR::Simple - Simple codec for the CBOR serialization format


=head1 SYNOPSIS

=begin code :lang<raku>

use CBOR::Simple;
my $cbor = cbor-encode($value);
my $val1 = cbor-decode($cbor);               # Fails if more data past first decoded value
my $val2 = cbor-decode($cbor, my $pos = 0);  # Updates $pos after decoding first value

# By default, cbor-decode() marks partially corrupt parsed structures with
# Failure nodes at the point of corruption
my $bad = cbor-decode(buf8.new(0x81 xx 3));  # [[[Failure]]]

# Callers can instead force throwing exceptions on any error
my $*CBOR_SIMPLE_FATAL_ERRORS = True;
my $bad = cbor-decode(buf8.new(0x81 xx 3));  # BOOM!

=end code


=head1 DESCRIPTION

CBOR::Simple is a trivial implementation of the core functionality of the
L<CBOR serialization format|https://cbor.io/>, implementing the standard as of
L<RFC 8949|https://tools.ietf.org/html/rfc8949>.

Currently known NOT to work:

=item 16-bit floats (num16)

=item Indefinite length maps

=item Pass-through of unrecognized simple values

=item Special decoding for registered tags other than numbers 0..3


=head2 SPECIAL CASES

=item CBOR's C<null> is translated as C<Any> in Raku

=item CBOR's C<undefined> is translated as C<Mu> in Raku

=item C<Instant> and C<DateTime> are both written as tag 1 (epoch-based date/time)

=item Both tag 0 (date/time string) and tag 1 (epoch-based date/time) are read as C<DateTime>

=item CBOR strings claiming to be longer than C<2⁶‭³‭-1> are treated as malformed


=head1 AUTHOR

Geoffrey Broadwell <gjb@sonic.net>


=head1 COPYRIGHT AND LICENSE

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under
the Artistic License 2.0.

=end pod
