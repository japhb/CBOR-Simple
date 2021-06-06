[![Actions Status](https://github.com/japhb/CBOR-Simple/workflows/test/badge.svg)](https://github.com/japhb/CBOR-Simple/actions)

NAME
====

CBOR::Simple - Simple codec for the CBOR serialization format

SYNOPSIS
========

```raku
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
```

DESCRIPTION
===========

CBOR::Simple is a trivial implementation of the core functionality of the [CBOR serialization format](https://cbor.io/), implementing the standard as of [RFC 8949](https://tools.ietf.org/html/rfc8949).

NYI
---

Currently known NOT to work:

  * Encoding 16-bit floats (num16) -- decoding num16 works

  * Special decoding for registered tags other than numbers 0..5, 30, and 55799

DATETIME AND INSTANT
--------------------

Raku's builtin time handling is richer than the default CBOR data model, so the following mappings apply:

  * `Instant` and `DateTime` are both written as tag 1 (epoch-based date/time)

  * Other `Dateish` are written as tag 0 (date/time string)

  * Tag 0 (date/time string) is parsed as `DateTime`

  * Tag 1 (epoch-based date/time) is parsed via `Instant.from-posix()`

OTHER SPECIAL CASES
-------------------

  * CBOR's `null` is translated as `Any` in Raku

  * CBOR's `undefined` is translated as `Mu` in Raku

  * CBOR strings claiming to be longer than `2⁶‭³‭-1` are treated as malformed

  * `cbor-diagnostic()` always adds encoding indicators for float values

AUTHOR
======

Geoffrey Broadwell <gjb@sonic.net>

COPYRIGHT AND LICENSE
=====================

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

