unit module CBOR::Simple:auth<zef:japhb>:api<0>:ver<0.0.6>;

use nqp;
use TinyFloats;


enum CBORMajorType (
    CBOR_UInt  => 0,
    CBOR_NInt  => 1 +< 5,
    CBOR_BStr  => 2 +< 5,
    CBOR_TStr  => 3 +< 5,
    CBOR_Array => 4 +< 5,
    CBOR_Map   => 5 +< 5,
    CBOR_Tag   => 6 +< 5,
    CBOR_SVal  => 7 +< 5,
);


enum CBORMagicNumber (
    CBOR_MajorType_Mask => 0xE0,
    CBOR_Argument_Mask  => 0x1F,

    CBOR_False => 20,
    CBOR_True  => 21,
    CBOR_Null  => 22,
    CBOR_Undef => 23,

    CBOR_1Byte => 24,
    CBOR_2Byte => 25,
    CBOR_4Byte => 26,
    CBOR_8Byte => 27,

    CBOR_Indefinite_Break => 31,
);

enum CBORMinMax (
    CBOR_Max_UInt_1Byte => 255,
    CBOR_Max_UInt_2Byte => 65535,
    CBOR_Max_UInt_4Byte => 4294967295,
    CBOR_Max_UInt_8Byte => 18446744073709551615,
    CBOR_Max_UInt_63Bit => 9223372036854775807,

    CBOR_Min_NInt_1Byte => -256,
    CBOR_Min_NInt_2Byte => -65536,
    CBOR_Min_NInt_4Byte => -4294967296,
    CBOR_Min_NInt_8Byte => -18446744073709551616,
    CBOR_Min_NInt_63Bit => -9223372036854775808,
);


enum CBORTagNumber (
    CBOR_Tag_DateTime_String  => 0,
    CBOR_Tag_DateTime_Number  => 1,
    CBOR_Tag_Unsigned_BigInt  => 2,
    CBOR_Tag_Negative_BigInt  => 3,
    CBOR_Tag_Decimal_Fraction => 4,
    CBOR_Tag_Bigfloat         => 5,
    CBOR_Tag_Rational         => 30,
    CBOR_Tag_Self_Described   => 55799,
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


# Buffer read/write constants
my int $ne8  = nqp::bitor_i(nqp::const::BINARY_SIZE_8_BIT, NativeEndian);
my int $be16 = nqp::bitor_i(nqp::const::BINARY_SIZE_16_BIT, BigEndian);
my int $be32 = nqp::bitor_i(nqp::const::BINARY_SIZE_32_BIT, BigEndian);
my int $be64 = nqp::bitor_i(nqp::const::BINARY_SIZE_64_BIT, BigEndian);


# Precache a utf8 encoder, since we'll be doing it a LOT
my $utf8-encoder = Encoding::Registry.find("utf8").encoder;


# Don't use the RFC 8949 map key sorting, it's really slow
constant RFC8949_Map_Key_Sort = False;


# Encode an arbitrary value to CBOR, possibly with leading self-describing tag 55799
multi cbor-encode(Mu $value, :$cbor-self-tag) is export {
    my $pos;
    $cbor-self-tag
    ?? cbor-encode($value, $pos = 3, buf8.new(0xd9, 0xd9, 0xf7))
    !! cbor-encode($value, $pos = 0)
}

# Encode an arbitrary value to CBOR, specifying a buffer position to begin writing
multi cbor-encode(Mu $value, Int:D $pos is rw, Buf:D $buf = buf8.new) is export {
    my sub write-uint(int $major-type, int $value) {
        if $value < CBOR_1Byte {
            nqp::writeuint($buf, $pos++, $major-type + $value, $ne8);
        }
        elsif $value <= CBOR_Max_UInt_1Byte {
            nqp::writeuint($buf, $pos++, $major-type + CBOR_1Byte, $ne8);
            nqp::writeuint($buf, $pos++, $value, $ne8);
        }
        elsif $value <= CBOR_Max_UInt_2Byte {
            nqp::writeuint($buf, $pos++, $major-type + CBOR_2Byte, $ne8);
            nqp::writeuint($buf, $pos, $value, $be16);
            $pos += 2;
        }
        elsif $value <= CBOR_Max_UInt_4Byte {
            nqp::writeuint($buf, $pos++, $major-type + CBOR_4Byte, $ne8);
            nqp::writeuint($buf, $pos, $value, $be32);
            $pos += 4;
        }
        else {
            nqp::writeuint($buf, $pos++, $major-type + CBOR_8Byte, $ne8);
            nqp::writeuint($buf, $pos, $value, $be64);
            $pos += 8;
        }
    }

    my sub write-medium-uint(int $major-type, $value) {
        nqp::writeuint($buf, $pos++, $major-type + CBOR_8Byte, $ne8);
        $buf.write-uint64($pos, $value, BigEndian);
        $pos += 8;
    }

    my &encode = -> $value {
    # Defined values
        with $value {
            # First classify by general role, then by actual type

            # Check for Numeric before Stringy so allomorphs prefer Numeric
            if nqp::istype($_, Numeric) {
                if nqp::istype($_, Bool) {
                    nqp::writeuint($buf, $pos++, CBOR_SVal + ($_ ?? CBOR_True !! CBOR_False), $ne8);
                }
                elsif nqp::istype($_, Int) {
                    # Small int
                    if CBOR_Min_NInt_63Bit <= $_ <= CBOR_Max_UInt_63Bit {
                        $_ >= 0 ?? write-uint(CBOR_UInt,   $_)
                                !! write-uint(CBOR_NInt, +^$_);
                    }
                    # Medium int
                    elsif CBOR_Min_NInt_8Byte <= $_ <= CBOR_Max_UInt_8Byte {
                        $_ >= 0 ?? write-medium-uint(CBOR_UInt,   $_)
                                !! write-medium-uint(CBOR_NInt, +^$_);
                    }
                    # Unsigned BigInt
                    elsif $_ >= 0 {
                        nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_Tag_Unsigned_BigInt, $ne8);
                        my @bytes = .polymod(256 xx *).reverse;
                        my $bytes = @bytes.elems;
                        write-uint(CBOR_BStr, $bytes);
                        $buf.splice($pos, $bytes, @bytes);
                        $pos += $bytes;
                    }
                    # Negative BigInt
                    else {
                        nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_Tag_Negative_BigInt, $ne8);
                        my @bytes = (+^$_).polymod(256 xx *).reverse;
                        my $bytes = @bytes.elems;
                        write-uint(CBOR_BStr, $bytes);
                        $buf.splice($pos, $bytes, @bytes);
                        $pos += $bytes;
                    }
                }
                elsif nqp::istype($_, Num) {
                    my $isnan = .isNaN;
                    my num32 $num32 = $_;

                    my $use32 = $num32 == $_ || $isnan && do {
                        my buf8 $nan .= new;
                        $nan.write-num64(0, $_, BigEndian);
                        $nan[4] == $nan[5] == $nan[6] == $nan[7] == 0
                    };

                    # my $bin16 = bin16-from-num($_);
                    # my $num16 = num-from-bin16($bin16);
                    # if $num16 == $_ {  # XXXX: What about NaN?
                    #     nqp::writeuint($buf, $pos++, CBOR_SVal + CBOR_2Byte, $ne8);
                    #     nqp::writeuint($buf, $pos, $bin16, $be16);
                    #     $pos += 2;
                    # }
                    if $use32 {
                        nqp::writeuint($buf, $pos++, CBOR_SVal + CBOR_4Byte, $ne8);
                        nqp::writenum($buf, $pos, $num32, $be32);

                        # Canonify NaN sign bit to 0, even on platforms with -NaN
                        nqp::writeuint($buf, $pos, nqp::readuint($buf, $pos, $ne8) +& 0x7F, $ne8)
                            if $isnan;

                        $pos += 4;
                    }
                    else {
                        nqp::writeuint($buf, $pos++, CBOR_SVal + CBOR_8Byte, $ne8);
                        nqp::writenum($buf, $pos, $_, $be64);

                        # Canonify NaN sign bit to 0, even on platforms with -NaN
                        nqp::writeuint($buf, $pos, nqp::readuint($buf, $pos, $ne8) +& 0x7F, $ne8)
                            if $isnan;

                        $pos += 8;
                    }
                }
                elsif nqp::istype($_, Rational) {
                    # write-uint(CBOR_Tag, CBOR_Tag_Rational);
                    nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_1Byte, $ne8);
                    nqp::writeuint($buf, $pos++, CBOR_Tag_Rational, $ne8);
                    nqp::writeuint($buf, $pos++, CBOR_Array + 2, $ne8);

                    my $nu := .numerator;
                    # Slow path for FatRats and "big" Rats
                    if nqp::istype($_, FatRat)
                    || $nu > CBOR_Max_UInt_63Bit
                    || $nu < CBOR_Min_NInt_63Bit {
                        encode($nu);
                        encode(.denominator);
                    }
                    # Fast path for "small" Rats
                    else {
                        $nu >= 0 ?? write-uint(CBOR_UInt,   $nu)
                                 !! write-uint(CBOR_NInt, +^$nu);
                        write-uint(CBOR_UInt, .denominator);
                    }
                }
                elsif nqp::istype($_, Instant) {
                    my $num = .to-posix[0].Num;
                    my $val = $num.Int == $num ?? $num.Int !! $num;

                    nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_Tag_DateTime_Number, $ne8);
                    encode($val);
                }
                elsif nqp::istype($_, Real) {
                    # XXXX: Pretend any other Real is a Num
                    encode(.Num);
                }
                else {
                    my $ex = "Don't know how to encode a {$value.^name}";
                    $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
                }
            }
            elsif nqp::istype($_, Stringy) {
                if nqp::istype($_, Str) {
                    my $utf8 := $utf8-encoder.encode-chars($_);
                    my $bytes = nqp::elems($utf8);
                    write-uint(CBOR_TStr, $bytes);
                    nqp::splice($buf, $utf8, $pos, $bytes);
                    $pos += $bytes;
                }
                elsif nqp::istype($_, Blob) {
                    my $bytes = .bytes;

                    write-uint(CBOR_BStr, $bytes);
                    $buf.splice($pos, $bytes, $_);
                    $pos += $bytes;
                }
                else {
                    my $ex = "Don't know how to encode a {$value.^name}";
                    $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
                }
            }
            # XXXX: Seq/Iterator?
            elsif nqp::istype($_, Positional) {
                write-uint(CBOR_Array, .elems);
                encode($_) for @$_;
            }
            elsif nqp::istype($_, Associative) {
                write-uint(CBOR_Map, .elems);
                if RFC8949_Map_Key_Sort {
                    my @pairs = .map: {
                        cbor-encode(.key, my $ = 0) => .value
                    };
                    @pairs.sort(*.key).map: {
                        my $bytes = .key.bytes;
                        $buf.splice($pos, $bytes, .key);
                        $pos += $bytes;
                        encode(.value);
                    }
                }
                else {
                    for .sort {
                        encode(.key);
                        encode(.value);
                    }
                }
            }
            elsif nqp::istype($_, Dateish) {
                if nqp::istype($_, DateTime) {
                    my $num = .Instant.to-posix[0].Num;
                    my $val = $num.Int == $num ?? $num.Int !! $num;

                    nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_Tag_DateTime_Number, $ne8);
                    encode($val);
                }
                else {
                    nqp::writeuint($buf, $pos++, CBOR_Tag + CBOR_Tag_DateTime_String, $ne8);
                    encode(.yyyy-mm-dd);
                }
            }
            else {
                my $ex = "Don't know how to encode a {$value.^name}";
                $*CBOR_SIMPLE_FATAL_ERRORS ?? die $ex !! fail $ex;
            }
        }
        # Undefined values
        else {
            # Any:U is CBOR null, other Mu:U is CBOR undefined
            nqp::writeuint($buf, $pos++, CBOR_SVal + (nqp::istype($value, Any)
                                                      ?? CBOR_Null !! CBOR_Undef), $ne8);
        }
    }

    encode($value);
    $buf
}


# Decode the first value from CBOR-encoded data
multi cbor-decode(Blob:D $cbor) is export {
    my $value := cbor-decode($cbor, my $pos = 0);
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

    my int $cbor-length = $cbor.bytes;
    my int $argument;

    my &read-uint = -> $allow-indefinite = False {
        $argument <  CBOR_1Byte ?? $argument !!
        $argument == CBOR_1Byte ?? nqp::readuint($cbor, $pos++, $ne8) !! do
        if $argument == CBOR_2Byte {
            my int $v = nqp::readuint($cbor, $pos, $be16);
            $pos += 2;
            $v
        }
        elsif $argument == CBOR_4Byte {
            my int $v = nqp::readuint($cbor, $pos, $be32);
            $pos += 4;
            $v
        }
        elsif $argument == CBOR_8Byte {
            my $v = nqp::readuint($cbor, $pos, $be64);
            $pos += 8;
            $v
        }
        elsif $argument == CBOR_Indefinite_Break {
            $allow-indefinite ?? Whatever
                              !! fail-malformed "Unexpected indefinite argument";
        }
        else {
            fail-malformed "Invalid argument $argument";
        }
    }

    my &decode = {
        my int $initial-byte = nqp::readuint($cbor, $pos++, $ne8);
        my int $major-type   = $initial-byte +& CBOR_MajorType_Mask;
        $argument = $initial-byte +& CBOR_Argument_Mask;

        $major-type == CBOR_UInt ??   read-uint() !!
        $major-type == CBOR_NInt ?? +^read-uint() !!
        do if $major-type == CBOR_BStr {
            my $bytes = read-uint(!$breakable);

            # Indefinite length
            if $bytes === Whatever {
                my buf8 $joined .= new;
                until (my $chunk := cbor-decode($cbor, $pos, :breakable)) =:= Break {
                    fail-malformed "Byte string chunk has wrong type"
                        unless nqp::istype($chunk, Buf);
                    $joined.append($chunk);
                }
                $joined
            }
            # Definite length
            elsif $bytes {
                fail-malformed "Unreasonably long byte string"
                    if $bytes > CBOR_Max_UInt_63Bit;

                fail-malformed "Byte string too short"
                    unless $cbor-length >= (my $a = $pos + $bytes);

                my $buf := nqp::slice($cbor, $pos, $a - 1);
                $pos = $a;
                $buf
            }
            else { buf8.new }
        }
        elsif $major-type == CBOR_TStr {
            my $bytes = read-uint(!$breakable);

            # Indefinite length
            if $bytes === Whatever {
                my @chunks;
                until (my $chunk := cbor-decode($cbor, $pos, :breakable)) =:= Break {
                    fail-malformed "Text string chunk has wrong type"
                        unless nqp::istype($chunk, Str);
                    @chunks.push($chunk);
                }
                @chunks.join
            }
            # Definite length
            elsif $bytes {
                fail-malformed "Unreasonably long text string"
                    if $bytes > CBOR_Max_UInt_63Bit;

                fail-malformed "Text string too short"
                    unless $cbor-length >= (my $a = $pos + $bytes);

                my $str := nqp::p6box_s(nqp::decode(nqp::slice($cbor, $pos, $a - 1), 'utf8'));
                $pos = $a;
                $str
            }
            else { '' }
        }
        elsif $major-type == CBOR_Array {
            # Indefinite length
            $argument == CBOR_Indefinite_Break
            ?? do {
                my @array;
                until (my $item := cbor-decode($cbor, $pos, :breakable)) =:= Break {
                    @array.push($item);
                }
                @array
            }
            !! my @ = (^read-uint).map(&decode)
        }
        elsif $major-type == CBOR_Map {
            my %str-map;
            my %mu-map{Mu};

            # Indefinite length
            if $argument == CBOR_Indefinite_Break {
                loop {
                    my $k := cbor-decode($cbor, $pos, :breakable);
                    last if $k =:= Break;
                    (nqp::istype($k, Str) ?? %str-map !! %mu-map){$k} = decode;
                }
            }
            # Definite length
            else {
                (nqp::istype((my $k = decode), Str) ?? %str-map !! %mu-map){$k} = decode
                    for ^read-uint;
            }

            if %mu-map.elems {
                %mu-map{$_} = %str-map{$_} for %str-map.keys;
                %mu-map
            }
            else {
                %str-map
            }
        }
        elsif $major-type == CBOR_Tag {
            my $tag-number = read-uint;
            if $tag-number == CBOR_Tag_Rational {
                fail-malformed "Rational tag (30) does not contain an array with exactly two elements"
                    unless nqp::readuint($cbor, $pos++, $ne8) == CBOR_Array + 2;

                my $nu = decode;
                my $de = decode;
                fail-malformed "Rational tag (30) numerator is not an integer"
                    unless nqp::istype($nu, Int);
                fail-malformed "Rational tag (30) denominator is not a positive integer"
                    unless nqp::istype($de, Int) && $de > 0;

                $de <= CBOR_Max_UInt_8Byte ?? Rat.new(   $nu, $de)
                                           !! FatRat.new($nu, $de)
            }
            elsif $tag-number == CBOR_Tag_DateTime_Number {
                my $seconds := decode;
                fail-malformed "Epoch DateTime tag(1) does not contain a real number"
                    unless nqp::istype($seconds, Real);
                Instant.from-posix($seconds) // fail-malformed "Epoch DateTime could not be decoded"
            }
            elsif $tag-number == CBOR_Tag_DateTime_String {
                my $dt := decode;
                fail-malformed "DateTime tag (0) does not contain a string"
                    unless nqp::istype($dt, Str);
                DateTime.new($dt) // fail-malformed "DateTime string could not be parsed"
            }
            elsif $tag-number == CBOR_Tag_Unsigned_BigInt {
                my $bytes := decode;
                fail-malformed "Unsigned BigInt does not contain a byte string"
                    unless nqp::istype($bytes, Buf);
                my $value = 0;
                $value = $value * 256 + $_ for @$bytes;
                $value
            }
            elsif $tag-number == CBOR_Tag_Negative_BigInt {
                my $bytes := decode;
                fail-malformed "Negative BigInt does not contain a byte string"
                    unless nqp::istype($bytes, Buf);
                my $value = 0;
                $value = $value * 256 + $_ for @$bytes;
                +^$value
            }
            elsif $tag-number == CBOR_Tag_Decimal_Fraction {
                fail-malformed "Decimal Fraction tag (4) does not contain an array with exactly two elements"
                    unless nqp::readuint($cbor, $pos++, $ne8) == CBOR_Array + 2;

                my $exp = decode;
                my $man = decode;
                fail-malformed "Decimal Fraction tag (4) exponent is not an integer"
                    unless nqp::istype($exp, Int);
                fail-malformed "Decimal Fraction tag (4) mantissa is not an integer"
                    unless nqp::istype($man, Int);

                $exp >= 0 ?? $man * 10 ** $exp !! do {
                    my $de = 10 ** -$exp;
                    $de <= CBOR_Max_UInt_8Byte ?? Rat.new(   $man, $de)
                                               !! FatRat.new($man, $de)
                }
            }
            elsif $tag-number == CBOR_Tag_Bigfloat {
                fail-malformed "Bigfloat tag (5) does not contain an array with exactly two elements"
                    unless nqp::readuint($cbor, $pos++, $ne8) == CBOR_Array + 2;

                my $exp = decode;
                my $man = decode;
                fail-malformed "Bigfloat tag (5) exponent is not an integer"
                    unless nqp::istype($exp, Int);
                fail-malformed "Bigfloat tag (5) mantissa is not an integer"
                    unless nqp::istype($man, Int);

                $exp >= 0 ?? $man * 2 ** $exp !! do {
                    my $de = 2 ** -$exp;
                    $de <= CBOR_Max_UInt_8Byte ?? Rat.new(   $man, $de)
                                               !! FatRat.new($man, $de)
                }
            }
            # Self-tagged CBOR, just unwrap the decoded tag content
            elsif $tag-number == CBOR_Tag_Self_Described {
                decode
            }
            # XXXX: skipped tags 16..18, 21..29
            # XXXX: Handle more special tags

            else {
                Tagged.new(:$tag-number, :value(decode))
            }
        }
        else { # $major-type == CBOR_SVal
            my constant %svals = 20 => False, 21 => True, 22 => Any, 23 => Mu;

            if $argument < CBOR_False {
                fail-malformed "Unassigned simple value $argument";
            }
            elsif $argument <= CBOR_Undef {
                %svals{$argument}
            }
            elsif $argument == CBOR_1Byte {
                my $val  = nqp::readuint($cbor, $pos++, $ne8);
                my $fail = $val < 24 ?? "Badly formed" !!
                           $val < 32 ?? "Reserved"     !!
                                        "Unassigned"   ;
                fail-malformed "$fail simple value $val";
            }
            elsif $argument == CBOR_2Byte {
                my $v = num-from-bin16($cbor.read-uint16($pos, BigEndian));
                $pos += 2;
                $v
            }
            elsif $argument == CBOR_4Byte {
                my $v = $cbor.read-num32($pos, BigEndian);
                $pos += 4;
                $v
            }
            elsif $argument == CBOR_8Byte {
                my $v = $cbor.read-num64($pos, BigEndian);
                $pos += 8;
                $v
            }
            elsif $argument == CBOR_Indefinite_Break {
                $breakable ?? Break
                           !! fail-malformed "Unexpected break signal";
            }
            else {
                fail-malformed "Badly formed simple value $argument";
            }
        }
    }

    decode;
}


# Convert a CBOR-encoded value to human diagnostic form
multi cbor-diagnostic(Blob:D $cbor) is export {
    cbor-diagnostic($cbor, my $pos = 0)
}

# Convert a CBOR-encoded value to human diagnostic form, starting at $pos
multi cbor-diagnostic(Blob:D $cbor, Int:D $pos is rw, Bool:D :$breakable = False) is export {
    my $initial-byte = $cbor.read-uint8($pos++);
    my $major-type   = $initial-byte +& CBOR_MajorType_Mask;
    my $argument     = $initial-byte +& CBOR_Argument_Mask;

    my &read-uint = {
        if $argument < CBOR_1Byte {
            $argument
        }
        elsif $argument == CBOR_1Byte {
            $cbor.read-uint8($pos++)
        }
        elsif $argument == CBOR_2Byte {
            my $v = $cbor.read-uint16($pos, BigEndian);
            $pos += 2;
            $v
        }
        elsif $argument == CBOR_4Byte {
            my $v = $cbor.read-uint32($pos, BigEndian);
            $pos += 4;
            $v
        }
        elsif $argument == CBOR_8Byte {
            my $v = $cbor.read-uint64($pos, BigEndian);
            $pos += 8;
            $v
        }
        elsif $argument == CBOR_Indefinite_Break {
            Whatever
        }
        else {
            fail "argument($argument)"
        }
    }

    given $major-type {
        when CBOR_UInt {
            ~read-uint
        }
        when CBOR_NInt {
            ~(+^read-uint)
        }
        when CBOR_BStr {
            my $bytes = read-uint;

            # Indefinite length
            if $bytes === Whatever {
                # Peek and see if there are any chunks
                if $cbor.read-uint8($pos) == CBOR_SVal +| CBOR_Indefinite_Break {
                    "''_"
                }
                else {
                    my @chunks;
                    until (my $chunk := cbor-diagnostic($cbor, $pos, :breakable))
                          =:= Break {
                        @chunks.push($chunk);
                    }
                    '(_ ' ~ @chunks.join(', ') ~ ')';
                }
            }
            # Definite length
            elsif $bytes > CBOR_Max_UInt_63Bit {
                "'Unreasonably long byte string, length $bytes'"
            }
            else {
                my $buf = $cbor.subbuf($pos, $bytes);
                if $buf.bytes == $bytes {
                    $pos += $bytes;
                    "h'" ~ $buf.list.map(*.fmt('%02x')).join ~ "'"
                }
                else {
                    "'Byte string too short, {$buf.bytes} < $bytes bytes'"
                }
            }
        }
        when CBOR_TStr {
            my $bytes = read-uint;

            # Indefinite length
            if $bytes === Whatever {
                # Peek and see if there are any chunks
                if $cbor.read-uint8($pos) == CBOR_SVal +| CBOR_Indefinite_Break {
                    '""_'
                }
                else {
                    my @chunks;
                    until (my $chunk := cbor-diagnostic($cbor, $pos, :breakable))
                          =:= Break {
                        @chunks.push($chunk);
                    }
                    '(_ ' ~ @chunks.join(', ') ~ ')';
                }
            }
            # Definite length
            elsif $bytes > CBOR_Max_UInt_63Bit {
                "\"Unreasonably long text string, length $bytes\""
            }
            else {
                my $utf8 = $cbor.subbuf($pos, $bytes);
                if $utf8.bytes == $bytes {
                    $pos += $bytes;
                    # XXXX: JSON escaping?
                    '"' ~ $utf8.decode ~ '"'
                }
                else {
                    "\"Text string too short, {$utf8.bytes} < $bytes bytes\""
                }
            }
        }
        when CBOR_Array {
            # Indefinite length
            $argument == CBOR_Indefinite_Break
            ?? do {
                my @array;
                until (my $item := cbor-diagnostic($cbor, $pos, :breakable)) =:= Break {
                    @array.push($item);
                }
                '[_ ' ~ @array.join(', ') ~ ']'
            }
            !! '[' ~ (^read-uint).map({ cbor-diagnostic($cbor, $pos) }).join(', ') ~ ']'
        }
        when CBOR_Map {
            my @pairs;
            # Indefinite length
            if $argument == CBOR_Indefinite_Break {
                loop {
                    my $k := cbor-diagnostic($cbor, $pos, :breakable);
                    last if $k =:= Break;
                    @pairs.push($k => cbor-diagnostic($cbor, $pos));
                }
                '{_ ' ~ @pairs.fmt('%s: %s', ', ') ~ '}'
            }
            # Definite length
            else {
                for ^(read-uint) {
                    my $k = cbor-diagnostic($cbor, $pos);
                    my $v = cbor-diagnostic($cbor, $pos);
                    @pairs.push($k => $v);
                }
                '{' ~ @pairs.fmt('%s: %s', ', ') ~ '}'
            }
        }
        when CBOR_Tag {
            read-uint() ~ '(' ~ cbor-diagnostic($cbor, $pos) ~ ')'
        }
        when CBOR_SVal {
            my constant %svals = 20 => 'false', 21 => 'true',
                                 22 => 'null',  23 => 'undefined';
            sub JS-Num($v) {
                $v.isNaN   ??  'NaN'      !!
                $v ==  Inf ??  'Infinity' !!
                $v == -Inf ?? '-Infinity' !! do {
                    my $basic = (~$v).subst(/'e0'$/, '').subst(/'e'('+'|'-')'0'/, {"e$0"});
                    $basic.contains('.') ?? $basic !! $basic.subst(/('e' | $)/, {".0$0"})
                }
            }

            if $argument < CBOR_False {
                "simple($argument)"
            }
            elsif $argument <= CBOR_Undef {
                %svals{$argument}
            }
            elsif $argument == CBOR_1Byte {
                my $sval = $cbor.read-uint8($pos++);
                "simple($sval)"
            }
            elsif $argument == CBOR_2Byte {
                my $v = num-from-bin16($cbor.read-uint16($pos, BigEndian));
                $pos += 2;
                JS-Num($v) ~ '_1'
            }
            elsif $argument == CBOR_4Byte {
                my $v = $cbor.read-num32($pos, BigEndian);
                $pos += 4;
                JS-Num($v) ~ '_2'
            }
            elsif $argument == CBOR_8Byte {
                my $v = $cbor.read-num64($pos, BigEndian);
                $pos += 8;
                JS-Num($v) ~ '_3'
            }
            elsif $breakable && $argument == CBOR_Indefinite_Break {
                Break
            }
            else {
                "simple($argument)"
            }

        }
    }
}


=begin pod

=head1 NAME

CBOR::Simple - Simple codec for the CBOR serialization format


=head1 SYNOPSIS

=begin code :lang<raku>

use CBOR::Simple;

# Encode a Raku value to CBOR, or vice-versa
my $cbor = cbor-encode($value);
my $val1 = cbor-decode($cbor);               # Fails if more data past first decoded value
my $val2 = cbor-decode($cbor, my $pos = 0);  # Updates $pos after decoding first value

# By default, cbor-decode() marks partially corrupt parsed structures with
# Failure nodes at the point of corruption
my $bad  = cbor-decode(buf8.new(0x81 xx 3));  # [[[Failure]]]

# Callers can instead force throwing exceptions on any error
my $*CBOR_SIMPLE_FATAL_ERRORS = True;
my $bad  = cbor-decode(buf8.new(0x81 xx 3));  # BOOM!

# Decode CBOR into diagnostic text, used for checking encodings and complex structures
my $diag = cbor-diagnostic($cbor);

=end code


=head1 DESCRIPTION

CBOR::Simple is a trivial implementation of the core functionality of the
L<CBOR serialization format|https://cbor.io/>, implementing the standard as of
L<RFC 8949|https://tools.ietf.org/html/rfc8949>.


=head2 NYI

Currently known NOT to work:

=item Encoding 16-bit floats (num16) -- decoding num16 works

=item Special decoding for registered tags other than numbers 0..5 and 30


=head2 DATETIME AND INSTANT

Raku's builtin time handling is richer than the default CBOR data model, so the
following mappings apply:

=item C<Instant> and C<DateTime> are both written as tag 1 (epoch-based date/time)

=item Other C<Dateish> are written as tag 0 (date/time string)

=item Tag 0 (date/time string) is parsed as C<DateTime>

=item Tag 1 (epoch-based date/time) is parsed via C<Instant.from-posix()>


=head2 OTHER SPECIAL CASES

=item CBOR's C<null> is translated as C<Any> in Raku

=item CBOR's C<undefined> is translated as C<Mu> in Raku

=item CBOR strings claiming to be longer than C<2⁶‭³‭-1> are treated as malformed

=item C<cbor-diagnostic()> always adds encoding indicators for float values


=head1 AUTHOR

Geoffrey Broadwell <gjb@sonic.net>


=head1 COPYRIGHT AND LICENSE

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under
the Artistic License 2.0.

=end pod
