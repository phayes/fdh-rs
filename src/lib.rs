//! Full Domain Hash
//!
//! A Full Domain Hash (FDH) is a cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.
//!
//! We construct an FDH by computing a number of cycles where `cycles=(target length)/(digest length) + 1`. We then compute `FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`, where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are `u32`.
//!
//! FDHs are usually used with an RSA signature scheme where the target length is the size of the key. See [https://en.wikipedia.org/wiki/Full_Domain_Hash](https://en.wikipedia.org/wiki/Full_Domain_Hash)
//!
//! This crate makes extensive use of the [`digest`](/digest) crate's cryptograhic hash traits, so most useful methods are implemented as part of `digest` traits. These traits are re-exported for convenience. See [https://github.com/RustCrypto/hashes](https://github.com/RustCrypto/hashes) for a list of compatible hashes.
//!
//! # Example
//! ```
//! use sha2::Sha256;
//! use fdh::{FullDomainHash, Input, VariableOutput};
//!   
//! // Expand SHA256 from 256 bits to 1024 bits.
//! let output_bits = 1024;
//! let output_bytes = 1024 / 8;
//! let mut hasher = FullDomainHash::<Sha256>::new(output_bytes).unwrap();
//! hasher.input(b"ATTACK AT DAWN");
//! let result = hasher.vec_result();
//! ```
//!
//! # `no_std`
//!
//! This crate also supports `no_std`.
//!
//! ```
//! #![no_std]
//! use sha2::Sha256;
//! use fdh::{FullDomainHash, Input, ExtendableOutput, XofReader};
//!   
//! // Expand SHA256 from 256 bits to 512 bits (and beyond!), reading it in 16 byte chunks.
//! let mut hasher = FullDomainHash::<Sha256>::default();
//! hasher.input(b"ATTACK AT DAWN");
//! let mut reader = hasher.xof_result();
//! let mut read_buf = <[u8; 16]>::default();
//!
//! // Read the first 16 bytes into read_buf
//! reader.read(&mut read_buf);
//!
//! // Read the second 16 bytes into read_buf
//! reader.read(&mut read_buf);
//!
//! // If we want, we can just keep going, reading as many bits as we want indefinitely.
//! reader.read(&mut read_buf);
//! reader.read(&mut read_buf);
//! ```

#![no_std]
use digest::Digest;
pub use digest::{ExtendableOutput, Input, Reset, VariableOutput, XofReader};
use failure::Fail;
use generic_array::GenericArray;

#[cfg(feature = "std")]
extern crate std;

#[derive(Clone, Debug, Default)]
pub struct FullDomainHash<H: Digest> {
    output_size: usize,
    inner_hash: H,
    current_suffix: u32,
    read_buf: GenericArray<u8, H::OutputSize>, // Used for digest::XofReader
    read_buf_pos: usize,                       // Used for digest::XofReader
}

/// Error types
#[cfg(feature = "std")]
#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "fdh: Cannot find intial suffix for a digest less than the desired max.")]
    NoDigestUnder,
}

impl<H: Digest + Clone> FullDomainHash<H> {
    /// Create new hasher instance with the given output size and initialization vector.
    ///
    /// The final hash will be `FDH(M) = HASH(M||IV) || HASH(M||IV+1) || ... || HASH(M||IV+N)`
    /// where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, `IV` is the initialization vector, and `N` is the number of cycles requires for the output length.
    ///
    /// If the initialization vector is large enough, it will "wrap around" from `xFFxFFxFFxFF` to `x00x00x00x00` using modular addition.
    pub fn with_iv(output_size: usize, iv: u32) -> Self {
        FullDomainHash {
            output_size,
            inner_hash: H::new(),
            current_suffix: iv,
            read_buf: GenericArray::default(),
            read_buf_pos: 0,
        }
    }

    /// Set the suffix that is appended to the message before hashing.
    ///
    /// This is useful when seaching for a hash output that has certain properties (for example is smaller than `n` in an RSA-FDH scheme.)
    pub fn set_suffix(&mut self, suffix: u32) {
        self.current_suffix = suffix;
    }

    // Utility function for reader
    fn fill_buffer(&mut self) {
        // If we are at position 0, then finalize the hash and read into the local buffer
        if self.read_buf_pos == 0 {
            let mut inner_hash = self.inner_hash.clone();

            // Append the final x00, x01, x02 etc.
            inner_hash.input(u32_to_u8_array(self.current_suffix));

            // Fill the buffer
            self.read_buf = inner_hash.result();

            // Increment the current suffix
            self.current_suffix = self.current_suffix.wrapping_add(1);
        }
    }

    fn read_buf_pos_mod_add(&mut self, rhs: usize) {
        if rhs > self.read_buf.len() {
            panic!("fdh: Cannot increment buffer position a larger amount than the buffer itself. This is a bug, please report it at https://github.com/phayes/fdh-rs/issues");
        }
        if self.read_buf_pos + rhs > self.read_buf.len() - 1 {
            self.read_buf_pos = rhs - (self.read_buf.len() - self.read_buf_pos);
        } else {
            self.read_buf_pos += rhs;
        }
    }

    /// Search for a digest value that is numerically less than the provided maximum by iterating over initial suffixes. Return the resulting digest and initialization value.
    ///
    /// This is useful when the full-domain-hash needs to be less than some value. For example modulus `n` in RSA-FDH.
    ///  
    ///  - `initial_iv` should be randomly generated.
    ///  - `max` should be the maximum allowed value in big endian format. For an RSA-FDH this would be the modulus `n`.
    ///
    /// # Example
    /// ```rust,no_run
    /// let mut hasher = FullDomainHash::<Sha512>::new(64)?;
    /// hasher.input(b"ATTACKATDAWN");
    /// let iv: u32 = rng.gen();
    /// let (digest, iv) = hasher.results_under(iv, priv_key.n())?;
    /// ```
    #[cfg(feature = "std")]
    pub fn results_under(
        self,
        initial_iv: u32,
        max: &num_bigint_dig::BigUint,
    ) -> Result<(std::vec::Vec<u8>, u32), Error> {
        let mut current_suffix = initial_iv;

        loop {
            let mut hasher = FullDomainHash {
                output_size: self.output_size,
                inner_hash: self.inner_hash.clone(),
                current_suffix: current_suffix,
                read_buf: GenericArray::default(),
                read_buf_pos: 0,
            };
            hasher.set_suffix(current_suffix);
            let res = VariableOutput::vec_result(hasher);
            if &num_bigint_dig::BigUint::from_bytes_be(&res) < max {
                return Ok((res, current_suffix));
            } else {
                current_suffix = current_suffix.wrapping_add(1);

                // We've exausted the search space, give up.
                if current_suffix == initial_iv {
                    return Err(Error::NoDigestUnder);
                }
            }
        }
    }
}

#[cfg(feature = "std")]
impl<H: Digest + Clone> VariableOutput for FullDomainHash<H> {
    /// Create new hasher instance with the given output size.
    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        Ok(FullDomainHash::with_iv(output_size, 0))
    }

    /// Get output size of the hasher instance.
    fn output_size(&self) -> usize {
        self.output_size
    }

    /// Retrieve result via closure and consume hasher.
    ///
    /// Closure is guaranteed to be called, length of the buffer passed to it will be equal to output_size.
    ///
    /// You should probably use [`vec_result()`](#method.vec_result) instead.
    fn variable_result<F: FnOnce(&[u8])>(mut self, f: F) {
        let num_inner = self.output_size / H::output_size();
        let remainder = self.output_size % H::output_size();

        let mut buf = std::vec::Vec::<u8>::with_capacity(self.output_size);

        for _ in 0..num_inner {
            self.fill_buffer();
            buf.extend_from_slice(self.read_buf.as_slice());
        }

        if remainder != 0 {
            self.fill_buffer();
            buf.extend_from_slice(&self.read_buf.as_slice()[..remainder]);
        }
        f(buf.as_slice());
    }
}

impl<H: Digest> Input for FullDomainHash<H> {
    /// Digest input data
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.inner_hash.input(data);
    }
}

impl<H: Digest> Reset for FullDomainHash<H> {
    /// Reset the hasher, discarding all internal state.
    fn reset(&mut self) {
        self.inner_hash.reset();
    }
}

#[cfg(feature = "std")]
impl<H: Digest> std::io::Write for FullDomainHash<H> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let len = buf.len();
        self.input(buf);
        Ok(len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<H: Digest + Clone> ExtendableOutput for FullDomainHash<H> {
    type Reader = Self;

    fn xof_result(self) -> Self::Reader {
        self
    }
}

impl<H: Digest + Clone> digest::XofReader for FullDomainHash<H> {
    fn read(&mut self, buffer: &mut [u8]) {
        let dest_len = buffer.len();
        let source_len = self.read_buf.len();

        // Direct copy (happy path)
        if source_len == dest_len {
            self.fill_buffer();
            buffer[..].copy_from_slice(&self.read_buf.as_slice()[..]);
        } else {
            let mut n = 0; // amount written
            while n < dest_len {
                self.fill_buffer();

                // Fill either what's left in the buffer, or what's left to write to the client.
                let fill_amount = core::cmp::min(source_len - self.read_buf_pos, dest_len - n);
                let read_slice =
                    &self.read_buf.as_slice()[self.read_buf_pos..(self.read_buf_pos + fill_amount)];
                buffer[n..(n + fill_amount)].copy_from_slice(read_slice);

                self.read_buf_pos_mod_add(fill_amount);
                n += fill_amount;
            }
        }
    }
}

// Utility function to go from u32 to [u8; 4]
fn u32_to_u8_array(x: u32) -> [u8; 4] {
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

#[cfg(test)]
mod tests {
    use hex;
    use sha1::Sha1;
    use sha2::Sha256;

    #[test]
    #[cfg(feature = "std")]
    fn sha256_std_test() {
        use crate::{FullDomainHash, Input, Reset, VariableOutput};

        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(256 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(
            result,
            "d06924c6a0fc0f30463308895add96e9f2cf48e477a187d1f4079536276958e5"
        );

        // Test Reset
        let mut hasher = FullDomainHash::<Sha256>::new(256 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        hasher.reset();
        hasher.input(b"ATTACK AT ");
        hasher.input(b"DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(
            result,
            "d06924c6a0fc0f30463308895add96e9f2cf48e477a187d1f4079536276958e5"
        );

        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(128 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "d06924c6a0fc0f30463308895add96e9");

        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x01' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::new(264 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(
            result,
            "d06924c6a0fc0f30463308895add96e9f2cf48e477a187d1f4079536276958e538"
        );

        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x01' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x02' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x03' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::new(1024 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "d06924c6a0fc0f30463308895add96e9f2cf48e477a187d1f4079536276958e53843af10006e0a1da85b70d5bb8be9b29a40667465d771cbac89f671d0b88b31fa91a4c9cdd497c10e32971eceac3a5abeb533f36ba77803bf2247830db07548183421bf034229e7a44424ff02b04e4595a32c916e29e30eedb7d05059bcf852");

        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits, using 4294967294 as the initialization vector.
        // echo -n -e 'ATTACK AT DAWN\xFF\xFF\xFF\xFE' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\xFF\xFF\xFF\xFF' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00\x00\x00\x01' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::with_iv(1024 / 8, 4294967294);
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "87c26af69c716e524e5600249f049525fa12a273b2ebdc9ee29ae9d004712d13774bebfcb7c362064e64619239060d775e127f2432640125fa6fd34b792b4435d06924c6a0fc0f30463308895add96e9f2cf48e477a187d1f4079536276958e53843af10006e0a1da85b70d5bb8be9b29a40667465d771cbac89f671d0b88b31");
    }

    #[test]
    fn sha256_no_std_test() {
        // Testing with no_std;
        use crate::{ExtendableOutput, FullDomainHash, Input, XofReader};

        let mut hasher = FullDomainHash::<Sha256>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 8]>::default();

        // d06924c6a0fc0f30
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0xd0, 0x69, 0x24, 0xc6, 0xa0, 0xfc, 0x0f, 0x30]);

        // 463308895add96e9
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0x46, 0x33, 0x08, 0x89, 0x5a, 0xdd, 0x96, 0xe9]);

        // f2cf48e477a187d1
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0xf2, 0xcf, 0x48, 0xe4, 0x77, 0xa1, 0x87, 0xd1]);

        // f4079536276958e5
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0xf4, 0x07, 0x95, 0x36, 0x27, 0x69, 0x58, 0xe5]);

        // 3843af10006e0a1d
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0x38, 0x43, 0xaf, 0x10, 0x00, 0x6e, 0x0a, 0x1d]);

        // Test with an odd number (21 in the case does not fit nicely into 32)
        let mut hasher = FullDomainHash::<Sha256>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 21]>::default();

        // d06924c6a0fc0f30463308895add96e9f2cf48e477
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0xd0, 0x69, 0x24, 0xc6, 0xa0, 0xfc, 0x0f, 0x30, 0x46, 0x33, 0x08, 0x89, 0x5a, 0xdd,
                0x96, 0xe9, 0xf2, 0xcf, 0x48, 0xe4, 0x77
            ]
        );

        // a187d1f4079536276958e53843af10006e0a1da85b
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0xa1, 0x87, 0xd1, 0xf4, 0x07, 0x95, 0x36, 0x27, 0x69, 0x58, 0xe5, 0x38, 0x43, 0xaf,
                0x10, 0x00, 0x6e, 0x0a, 0x1d, 0xa8, 0x5b
            ]
        );

        // Test where output size is larger than hash output size (21 > 20) using Sha1
        // 5355fb9836f1b3753273a837155abed75623a9393c
        let mut hasher = FullDomainHash::<Sha1>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 21]>::default();
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x53, 0x55, 0xfb, 0x98, 0x36, 0xf1, 0xb3, 0x75, 0x32, 0x73, 0xa8, 0x37, 0x15, 0x5a,
                0xbe, 0xd7, 0x56, 0x23, 0xa9, 0x39, 0x3c
            ]
        );

        // Test where output size and digest size are the same using Sha1.
        // 5355fb9836f1b3753273a837155abed75623a939
        let mut hasher = FullDomainHash::<Sha1>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 20]>::default();
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x53, 0x55, 0xfb, 0x98, 0x36, 0xf1, 0xb3, 0x75, 0x32, 0x73, 0xa8, 0x37, 0x15, 0x5a,
                0xbe, 0xd7, 0x56, 0x23, 0xa9, 0x39
            ]
        );
    }

}
