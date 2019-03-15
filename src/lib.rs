//! Full Domain Hash
//!
//! A Full Domain Hash (FDH) is a cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.
//!
//! We construct an FDH by computing a number of cycles where `cycles=(target length)/(digest length) + 1`. We then compute `FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`, where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are `u8` (`\x01`, `\x02` etc).
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
    current_suffix: u8,
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
    /// Create new hasher instance with the given output size and intial suffix.
    ///
    /// The final hash will be `FDH(M) = HASH(M||S) || HASH(M||S+1) || ... || HASH(M||S+N)`
    /// where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, `S` is `initial_suffix`, and `N` is the number of cycles requires for the output length.
    ///
    /// If `initial_suffix` is large enough, it will "wrap around" from `xFF` to `x00` using modular addition.
    pub fn with_initial_suffix(
        output_size: usize,
        initial_suffix: u8,
    ) -> Result<Self, digest::InvalidOutputSize> {
        Ok(FullDomainHash {
            output_size,
            inner_hash: H::new(),
            current_suffix: initial_suffix,
            read_buf: GenericArray::default(),
            read_buf_pos: 0,
        })
    }

    /// Set the suffix that is appended to the message before hashing.
    ///
    /// This is useful when seaching for a hash output that has certain properties (for example is smaller than `n` in an RSA-FDH scheme.)
    pub fn set_suffix(&mut self, suffix: u8) {
        self.current_suffix = suffix;
    }

    // Utility function for reader
    fn fill_buffer(&mut self) {
        // If we are at position 0, then finalize the hash and read into the local buffer
        if self.read_buf_pos == 0 {
            let mut inner_hash = self.inner_hash.clone();

            // Append the final x00, x01, x02 etc.
            inner_hash.input([self.current_suffix]);

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
    ///  - `initial_suffix` should be randomly generated.
    ///  - `max` should be the maximum allowed value in big endian format. For an RSA-FDH this would be the modulus `n`.
    #[cfg(feature = "std")]
    pub fn results_under(
        self,
        initial_suffix: u8,
        max: &[u8],
    ) -> Result<(std::vec::Vec<u8>, u8), Error> {
        let max = num_bigint::BigUint::from_bytes_be(max);
        let current_suffix = initial_suffix;

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
            if num_bigint::BigUint::from_bytes_be(&res) < max {
                return Ok((res, current_suffix));
            } else {
                current_suffix.wrapping_add(1);

                if current_suffix == initial_suffix {
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
        FullDomainHash::with_initial_suffix(output_size, 0)
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

#[cfg(test)]
mod tests {
    use hex;
    use sha1::Sha1;
    use sha2::Sha256;

    #[test]
    #[cfg(feature = "std")]
    fn sha256_std_test() {
        use crate::{FullDomainHash, Input, Reset, VariableOutput};

        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(256 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(
            result,
            "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f1"
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
            "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f1"
        );

        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(128 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb283");

        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 && echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(264 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(
            result,
            "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158"
        );

        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits
        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x02' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x03' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::new(1024 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158617fec3b813f834cd86ab0dd26b971c46b7ede451b490279628a265edf0a10691095675808b47c0add4300b3181a31109cbc31a945d05562ceb6cca0fea834d9c456fe1abf34a5a775ed572ce571b1dcca03b984102e666e9ab876876fb3af");

        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits, using 254 as the initial suffix.
        // echo -n -e 'ATTACK AT DAWN\xFE' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\xFF' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::with_initial_suffix(1024 / 8, 254).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "8b41c68cc83acfa422fb6a0c61c5c7a14eef381768d37375c78caf61d76e62b4a93a562946a7378fc3eca407eb44e81fef2be026e1ee340ba85a06f9b2e4fe84015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158617fec3b813f834cd86ab0dd26b971c46b7ede451b490279628a265edf0a10");
    }

    #[test]
    fn sha256_no_std_test() {
        // Testing with no_std;
        use crate::{ExtendableOutput, FullDomainHash, Input, XofReader};

        let mut hasher = FullDomainHash::<Sha256>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 8]>::default();

        // 015d53c7925b4434
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0x01, 0x5d, 0x53, 0xc7, 0x92, 0x5b, 0x44, 0x34]);

        // f00286fe2f0eb283
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0xf0, 0x02, 0x86, 0xfe, 0x2f, 0x0e, 0xb2, 0x83]);

        // 78a49300b159b896
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0x78, 0xa4, 0x93, 0x00, 0xb1, 0x59, 0xb8, 0x96]);

        // eb2356a7c4de95f1
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0xeb, 0x23, 0x56, 0xa7, 0xc4, 0xde, 0x95, 0xf1]);

        // 58617fec3b813f83
        reader.read(&mut read_buf);
        assert_eq!(read_buf, [0x58, 0x61, 0x7f, 0xec, 0x3b, 0x81, 0x3f, 0x83]);

        // Test with an odd number (21 in the case does not fit nicely into 32)
        let mut hasher = FullDomainHash::<Sha256>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 21]>::default();

        // 015d53c7925b4434f00286fe2f0eb28378a49300b1
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x01, 0x5d, 0x53, 0xc7, 0x92, 0x5b, 0x44, 0x34, 0xf0, 0x02, 0x86, 0xfe, 0x2f, 0x0e,
                0xb2, 0x83, 0x78, 0xa4, 0x93, 0x00, 0xb1
            ]
        );

        // 59b896eb2356a7c4de95f158617fec3b813f834cd8
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x59, 0xb8, 0x96, 0xeb, 0x23, 0x56, 0xa7, 0xc4, 0xde, 0x95, 0xf1, 0x58, 0x61, 0x7f,
                0xec, 0x3b, 0x81, 0x3f, 0x83, 0x4c, 0xd8
            ]
        );

        // Test where output size is larger than hash output size (21 > 20) using Sha1
        // 1adfc344b75ab9a77d70745f4ebb5a973c5d1f1d20
        let mut hasher = FullDomainHash::<Sha1>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 21]>::default();
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x1a, 0xdf, 0xc3, 0x44, 0xb7, 0x5a, 0xb9, 0xa7, 0x7d, 0x70, 0x74, 0x5f, 0x4e, 0xbb,
                0x5a, 0x97, 0x3c, 0x5d, 0x1f, 0x1d, 0x20
            ]
        );

        // Test where output size and digest size are the same using Sha1.
        // 1adfc344b75ab9a77d70745f4ebb5a973c5d1f1d
        let mut hasher = FullDomainHash::<Sha1>::default();
        hasher.input(b"ATTACK AT DAWN");
        let mut reader = hasher.xof_result();
        let mut read_buf = <[u8; 20]>::default();
        reader.read(&mut read_buf);
        assert_eq!(
            read_buf,
            [
                0x1a, 0xdf, 0xc3, 0x44, 0xb7, 0x5a, 0xb9, 0xa7, 0x7d, 0x70, 0x74, 0x5f, 0x4e, 0xbb,
                0x5a, 0x97, 0x3c, 0x5d, 0x1f, 0x1d
            ]
        );
    }

}
