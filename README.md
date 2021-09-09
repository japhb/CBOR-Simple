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

# Force the encoder to tag a value with a particular tag number
my $tagged = CBOR::Simple::Tagged.new(:$tag-number, :$value);
my $cbor   = cbor-encode($tagged);
```

DESCRIPTION
===========

CBOR::Simple is a trivial implementation of the core functionality of the [CBOR serialization format](https://cbor.io/), implementing the standard as of [RFC 8949](https://tools.ietf.org/html/rfc8949).

NYI
---

Currently known NOT to work:

  * Encoding *finite* 16-bit floats (num16); encoding 16-bit NaN and ±Inf, as well as decoding any num16 all work. This is a performance tradeoff rather than a technical limitation; detecting whether a finite num32 can be shrunk to 16 bits without losing information is costly and rarely results in space savings except in trivial cases (e.g. Nums containing only small integers).

  * Special decoding for registered tags *other than* numbers 0..5, 30, 100, 1004, and 55799. The rest are NYI (Not Yet Implemented), but many will be added over time in future releases.

DATE, DATETIME, INSTANT
-----------------------

Raku's builtin time handling is richer than the default CBOR data model (though certain tag extensions improve this), so the following mappings apply:

  * Encoding

    * `Instant` and `DateTime` are both written as tag 1 (epoch-based date/time) with integer (if lossless) or floating point content.

    * Other `Dateish` are written as tag 100 (RFC 8943 days since 1970-01-01).

  * Decoding

    * Tag 0 (date/time string) is parsed as a `DateTime`.

    * Tag 1 (epoch-based date/time) is parsed via `Instant.from-posix()`, and handles any Real type in the tag content.

    * Tag 100 (days since 1970-01-01) is parsed via `Date.new-from-daycount()`.

    * Tag 1004 (date string) is parsed as a `Date`.

UNDEFINED VALUES
----------------

  * CBOR's `null` is translated as `Any` in Raku.

  * CBOR's `undefined` is translated as `Mu` in Raku.

  * A real `Nil` in an array (which must be *bound*, not assigned) is encoded as a CBOR Absent tag (31). Absent values will be recognized on decode as well, but since array contents are *assigned* into their parent array during decoding, a `Nil` in an array will be translated to `Any` by Raku's array assignment semantics.

OTHER SPECIAL CASES
-------------------


  * CBOR strings claiming to be longer than `2⁶‭³‭-1` are treated as malformed

  * `cbor-diagnostic()` always adds encoding indicators for float values

AUTHOR
======

Geoffrey Broadwell <gjb@sonic.net>

COPYRIGHT AND LICENSE
=====================

Copyright 2021 Geoffrey Broadwell

This library is free software; you can redistribute it and/or modify it under the Artistic License 2.0.

