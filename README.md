## Full Domain Hash

[![Build Status](https://travis-ci.org/phayes/fdh-rs.svg?branch=master)](https://travis-ci.org/phayes/fdh-rs)
[![codecov](https://codecov.io/gh/phayes/fdh-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/fdh-rs)
[![docs](https://docs.rs/fdh/badge.svg)](https://docs.rs/fdh)
[![crates.io](https://meritbadge.herokuapp.com/fdh)](https://crates.io/crates/fdh)
[![patreon](https://img.shields.io/badge/patreon-donate-green.svg)](https://patreon.com/phayes)
[![flattr](https://img.shields.io/badge/flattr-donate-green.svg)](https://flattr.com/@phayes)


A Full Domain Hash (FDH) is a useful cryptographic construction that limits the domain of the resulting digest (for example ensuring the digest is less than modulus `n` in RSA). Secondarily, it can also be used to extend the size of a hash digest to an arbitrary length, turning a regular hash function into an XOF hash function.

We construct an FDH by computing a number of cycles where:

`cycles=(target length)/(digest length) + 1`

We then compute:

`FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`

Where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are single-byte `u8`.

FDHs are usually used with an RSA signature scheme where the target length is the size of the key, and the domain is less than modulus `n`. See https://en.wikipedia.org/wiki/Full_Domain_Hash

This crate makes extensive use of the [`digest`](/digest) crate's cryptograhic hash traits, so most useful methods are implemented as part of `digest` traits. These traits are re-exported for convenience. See [https://github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) for a list of compatible hashes.

## Example

```rust
  use sha2::Sha256;
  use fdh::{FullDomainHash, VariableOutput, Input};

  // Expand SHA256 from 256 bits to 1024 bits.
  let output_bits = 1024;
  let output_bytes = 1024 / 8;
  let mut hasher = FullDomainHash::<Sha256>::new(output_bytes)?;
  hasher.input(b"ATTACK AT DAWN");
  let result = hasher.vec_result();
```

## `no_std`

This crate also supports `no_std`, so it can be used in embedded or other settings with no allocation.

```rust
#![no_std]
use sha2::Sha256;
use fdh::{FullDomainHash, Input, ExtendableOutput, XofReader};

// Expand SHA256 from 256 bits to 512 bits (and beyond!), reading it in 16 byte chunks.
let mut hasher = FullDomainHash::<Sha256>::default();
hasher.input(b"ATTACK AT DAWN");
let mut reader = hasher.xof_result();
let mut read_buf = <[u8; 16]>::default();

// Read the first 16 bytes into read_buf
reader.read(&mut read_buf);

// Read the second 16 bytes into read_buf
reader.read(&mut read_buf);

// If we want, we can just keep going, reading as many bits as we want indefinitely.
reader.read(&mut read_buf);
reader.read(&mut read_buf);
```

## Restricted Domain

This crate also supports getting a digest that is within a specific domain. It follows an algorithim like so:

```
fn digest_in_domain(message, iv):
    digest = fdh(message, iv)
    while not in_domain(digest):
        iv++
        digest = fdh(message, iv)
    return digest, iv
```

The method `results_in_domain()` is provided to accomplish this. The helper methods `results_between()`, `results_lt()`, `results_gt()` are provided for the common case where the digest must be in a certain range.

An example that produces a digest that is odd:

```rust
use sha2::Sha512;
use fdh::{FullDomainHash, Input, VariableOutput};
use num_bigint::BigUint;
use num_integer::Integer;

// Get a full domain hash that is odd
let mut hasher = FullDomainHash::<Sha512>::new(64).unwrap();
hasher.input(b"ATTACKATDAWN");

fn digest_is_odd(digest: &[u8]) -> bool {
    BigUint::from_bytes_be(digest).is_odd()
}
let iv = 0;

let (digest, iv) = hasher.results_in_domain(iv, digest_is_odd).unwrap();
```

## Moving Window Full Domain Hash

This crate also includes an experimental Moving Window Full Domain Hash (MWFDH), more information can be found [here](https://github.com/phayes/fdh-rs/tree/master/src/movingwindow).

 ## Contributors
 
 1. Patrick Hayes ([linkedin](https://www.linkedin.com/in/patrickdhayes/)) ([github](https://github.com/phayes)) - Available for hire.
