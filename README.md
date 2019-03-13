Full Domain Hash
----------------

[![Build Status](https://travis-ci.org/phayes/fdh-rs.svg?branch=master)](https://travis-ci.org/phayes/fdh-rs)
[![codecov](https://codecov.io/gh/phayes/fdh-rs/branch/master/graph/badge.svg)](https://codecov.io/gh/phayes/fdh-rs)
[![docs](https://docs.rs/fdh/badge.svg)](https://docs.rs/fdh)


A Full Domain Hash (FDH) is a useful cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.

We construct an FDH by computing a number of cycles where `cycles=(target length)/(digest length) + 1`. We then compute `FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`, where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are binary (`\x01`, `\x02` etc).

FDHs are usually used with an RSA signature scheme where the target length is the size of the key. See https://en.wikipedia.org/wiki/Full_Domain_Hash

This crate makes extensive use of the [`digest`](/digest) crate's cryptograhic hash traits, so most useful methods are implemented as part of `digest` traits. These traits are re-exported for convenience. See [https://github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) for a list of compatible hashes.


Example
-------
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

`no_std`
-------

This crate also supports `no_std`. 

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
