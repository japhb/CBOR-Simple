use v6.d;
use Test;
use CBOR::Simple;


#| Simple converter utility: hex string to binary buf
sub hex-decode(Str:D $hex, $buf-type = buf8) is export {
    $buf-type.new($hex.comb(2).map(*.parse-base(16)))
}


#| Round trip testing to a hex stringification of the CBOR blob
multi matches(Mu $value, Str:D $cbor) is export {
    matches($value, hex-decode($cbor))
}

#| Round trip testing directly to a CBOR blob
multi matches(Mu $value, Buf:D $cbor) is export {
    subtest "$value.raku() handled correctly", {
        my $as-cbor  = cbor-encode($value);
        my $as-value = cbor-decode($cbor);

        is-deeply $as-cbor,  $cbor,  "cbor-encode produces correct blob";
        is-deeply $as-value, $value, "cbor-decode produces correct value" if $value  ~~ Any;
        is        $as-value, Mu,     "cbor-decode produces correct value" if $value !~~ Any;
    }
}


#| Unidirectional ENcoding testing, matching a hex stringification of the expected CBOR blob
multi encodes-to(Mu $value, Str:D $cbor) is export {
    encodes-to($value, hex-decode($cbor))
}

#| Unidirectional ENcoding testing, matching an expected CBOR blob
multi encodes-to(Mu $value, Buf:D $cbor) is export {
    my $as-cbor = cbor-encode($value);
    is-deeply $as-cbor, $cbor, "cbor-encode({$value.raku}) produces correct blob"
}


#| Unidirectional DEcoding testing, from a hex stringification of the actual CBOR blob
multi decodes-to(Mu $value, Str:D $cbor) is export {
    decodes-to($value, hex-decode($cbor))
}

#| Unidirectional DEcoding testing, from an actual CBOR blob
multi decodes-to(Mu $value, Buf:D $cbor) is export {
    my $as-value = cbor-decode($cbor);
    my $as-hex   = $cbor.map(*.fmt('%02X')).join;

    if $value ~~ Any {
        is-deeply $as-value, $value, "cbor-decode($as-hex) produces correct value"
    }
    else {
        is        $as-value, $value, "cbor-decode($as-hex) produces correct value"
    }
}


#| Check for canonical diagnostic output using hex stringification of a CBOR blob
multi diagnostic-is(Str:D $diag, Str:D $cbor) is export {
    diagnostic-is($diag, hex-decode($cbor))
}

#| Check for canonical diagnostic output directly on a CBOR blob
multi diagnostic-is(Str:D $diag, Buf:D $cbor) is export {
    my $as-hex = $cbor.map(*.fmt('%02X')).join;

    is cbor-diagnostic($cbor), $diag, "cbor-diagnostic($as-hex) is correct"
}


# Failure can get "hidden" deep inside decoded structures, so fatalize instead
PROCESS::<$CBOR_SIMPLE_FATAL_ERRORS> = True;

#| Malformed input to decoder
sub malformed(Str:D $cbor, Str:D $reason) is export {
    throws-like { cbor-decode(hex-decode($cbor)) }, X::Malformed, "$reason ($cbor)"
}
