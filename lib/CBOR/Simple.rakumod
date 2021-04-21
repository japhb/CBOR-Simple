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

enum CBORSizedType is export (
    CBOR_UInt8  => CBOR_UInt + 24,
    CBOR_UInt16 => CBOR_UInt + 25,
    CBOR_UInt32 => CBOR_UInt + 26,
    CBOR_UInt64 => CBOR_UInt + 27,

    CBOR_NInt8  => CBOR_NInt + 24,
    CBOR_NInt16 => CBOR_NInt + 25,
    CBOR_NInt32 => CBOR_NInt + 26,
    CBOR_NInt64 => CBOR_NInt + 27,

    CBOR_Num16  => CBOR_SVal + 25,
    CBOR_Num32  => CBOR_SVal + 26,
    CBOR_Num64  => CBOR_SVal + 27,

    CBOR_BStrXS => CBOR_BStr + 0,
    CBOR_BStrS  => CBOR_BStr + 24,
    CBOR_BStrM  => CBOR_BStr + 25,
    CBOR_BStrL  => CBOR_BStr + 26,
    CBOR_BStrXL => CBOR_BStr + 27,
    CBOR_BStrIL => CBOR_BStr + 31,

    CBOR_TStrXS => CBOR_TStr + 0,
    CBOR_TStrS  => CBOR_TStr + 24,
    CBOR_TStrM  => CBOR_TStr + 25,
    CBOR_TStrL  => CBOR_TStr + 26,
    CBOR_TStrXL => CBOR_TStr + 27,
    CBOR_TStrIL => CBOR_TStr + 31,
);


# Introspection of tagged values
role Tagged[$number, $desc = ''] {
    method tag-number() { $number }
    method tag-desc()   { $desc   }
}


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
            else {
                # XXXX: BigInt
                ...
            }
        }
        when Num {
            # XXXX: Doesn't write short NaNs yet

            my num64 $num64 = $_;
            my num32 $num32 = $num64;
            # my num16 $num16 = $num64;

            # if $num16 == $num64 {
            #     # XXXX: write-num16 is UNAVAILABLE!
            #     die "Cannot write a 16-bit num";

            #     $buf.write-uint8($pos++, CBOR_Num16);
            #     $buf.write-num16($pos, $num16, BigEndian);
            #     $pos += 2;
            # }
            # elsif $num32 == $num64 {
            if $num32 == $num64 {
                $buf.write-uint8($pos++, CBOR_Num32);
                $buf.write-num32($pos, $num32, BigEndian);
                $pos += 4;
            }
            else {
                $buf.write-uint8($pos++, CBOR_Num64);
                $buf.write-num64($pos, $num64, BigEndian);
                $pos += 8;
            }
        }
        when DateTime {
            $buf.write-uint8($pos++, CBOR_Tag + 1);
            cbor-encode(.Num, $pos, $buf);
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
            fail "Don't know how to encode a {$value.^name}";
        }
    }

    $buf
}


# Decode the first value from CBOR-encoded data
multi cbor-decode(Blob:D $cbor) is export {
    cbor-decode($cbor, my $pos = 0)
}

# Decode the next value from CBOR-encoded data, starting at $pos
multi cbor-decode(Blob:D $cbor, Int:D $pos is rw) is export {
    my $initial-byte = $cbor.read-uint8($pos++);
    my $major-type   = $initial-byte +& 0xE0;
    my $argument     = $initial-byte +& 0x1F;

    my sub read-uint() {
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
        else {
            # XXXX: Not handling indefinite length yet
            fail "Invalid argument $argument";
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
            my $bytes = read-uint;
            my $buf = $cbor.subbuf($pos, $bytes);
            $pos += $bytes;
            $buf
        }
        when CBOR_TStr {
            my $bytes = read-uint;
            my $utf8  = $cbor.subbuf($pos, $bytes);
            $pos += $bytes;
            $utf8.decode
        }
        when CBOR_Array {
            my $elems = read-uint;
            my @ = (^$elems).map: { cbor-decode($cbor, $pos) }
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
            # XXXX: Not handling special tags
            my $tag-number = read-uint;
            cbor-decode($cbor, $pos) but Tagged[$tag-number]
        }
        when CBOR_SVal {
            my constant %svals = 20 => False, 21 => True, 22 => Any, 23 => Mu;

            if $argument < 20 {
                fail "Unassigned simple value $argument";
            }
            elsif $argument <= 23 {
                %svals{$argument}
            }
            elsif $argument == 24 {
                my $val  = $cbor.read-uint8($pos++);
                my $fail = $val < 24 ?? "Badly formed" !!
                           $val < 32 ?? "Reserved"     !!
                                        "Unassigned"   ;
                fail "$fail simple value $val";
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
            else {
                # XXXX: Not handling indefinite length stop code yet
                fail "Badly formed simple value $argument";
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
my $val  = cbor-decode($cbor);

=end code


=head1 DESCRIPTION

CBOR::Simple is a trivial implementation of the core functionality of the
L<CBOR serialization format|https://cbor.io/>, implementing the standard as of
L<RFC 8949|https://tools.ietf.org/html/rfc8949>.


=head1 AUTHOR

Geoffrey Broadwell <gjb@sonic.net>


=head1 COPYRIGHT AND LICENSE

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under
the Artistic License 2.0.

=end pod
