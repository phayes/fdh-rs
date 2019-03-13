Full Domain Hash
================

A Full Domain Hash (FDH) is a useful cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.

We construct an FDH by computing a number of cycles where `cycles=(target length)/(digest length) + 1`. We then compute `FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`, where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are binary (`\x01`, `\x02` etc).

FDHs are usually used with an RSA signature scheme where the target length is the size of the key. See https://en.wikipedia.org/wiki/Full_Domain_Hash


Example
-------
```rust
  use sha2::Sha256;
  use fdh::{FullDomainHash, VariableOutput, Input}

  // Expand SHA256 from 256 bits to 1024 bits.
  let output_bits = 1024;
  let output_bytes = 1024 / 8;
  let mut hasher = FullDomainHash::<Sha256>::new(output_bytes)?;
  hasher.input(b"ATTACK AT DAWN");
  let result = hasher.vec_result();
```
