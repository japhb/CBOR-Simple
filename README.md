[![Actions Status](https://github.com/japhb/CBOR-Simple/workflows/test/badge.svg)](https://github.com/japhb/CBOR-Simple/actions)

NAME
====

CBOR::Simple - Simple codec for the CBOR serialization format

SYNOPSIS
========

```raku
use CBOR::Simple;
my $cbor = cbor-encode($value);
my $val1 = cbor-decode($cbor);               # Fails if more data past first decoded value
my $val2 = cbor-decode($cbor, my $pos = 0);  # Updates $pos after decoding first value
```

DESCRIPTION
===========

CBOR::Simple is a trivial implementation of the core functionality of the [CBOR serialization format](https://cbor.io/), implementing the standard as of [RFC 8949](https://tools.ietf.org/html/rfc8949).

Currently known NOT to work:

  * 16-bit floats (num16)

  * Minimal-length NaN coding

  * Indefinite length encodings

  * Pass-through of unrecognized simple values

  * Special decoding for registered tags other than numbers 0..3

SPECIAL CASES
-------------

  * CBOR's `null` is translated as `Any` in Raku

  * CBOR's `undefined` is translated as `Mu` in Raku

  * `Instant` and `DateTime` are both written as tag 1 (epoch-based date/time)

  * Both tag 0 (date/time string) and tag 1 (epoch-based date/time) are read as `DateTime`

  * CBOR strings claiming to be longer than `2⁶‭³‭-1` are treated as malformed

AUTHOR
======

Geoffrey Broadwell <gjb@sonic.net>

COPYRIGHT AND LICENSE
=====================

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

