//! Full Domain Hash
//!
//! A Full Domain Hash (FDH) is a cryptographic construction that extends the size of a hash digest to an arbitrary length. For example, SHA256 can be expanded to 1024 bits instead of the usual 256 bits.
//! 
//! We construct an FDH by computing a number of cycles where `cycles=(target length)/(digest length) + 1`. We then compute `FDH(M) = HASH(M||0) || HASH(M||1) || ... || HASH(M||cycles−1)`, where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, and numerical values are `u8` (`\x01`, `\x02` etc).
//! 
//! FDHs are usually used with an RSA signature scheme where the target length is the size of the key. See [https://en.wikipedia.org/wiki/Full_Domain_Hash](https://en.wikipedia.org/wiki/Full_Domain_Hash)
//!
//! This crate makes extensive use of the [`digest`](/digest) crate's cryptograhic hash traits, so most useful methods are implemented as part of `digest` traits. These traits are re-exported for convenience.
//! 
//! # Example
//! ```
//! use sha2::Sha256;
//! use fdh::{FullDomainHash, VariableOutput, Input};
//! 
//! // Expand SHA256 from 256 bits to 1024 bits.
//! let output_bits = 1024;
//! let output_bytes = 1024 / 8;
//! let mut hasher = FullDomainHash::<Sha256>::new(output_bytes).unwrap();
//! hasher.input(b"ATTACK AT DAWN");
//! let result = hasher.vec_result();
//! ```


pub use digest::{VariableOutput, Input, Reset};
use digest::Digest;

#[derive(Clone)]
pub struct FullDomainHash<H: Digest> {
    output_size: usize,
    inner_hash: H,
    initial_count: u8,
}

impl<H: Digest + Clone> FullDomainHash<H> {

    /// Create new hasher instance with the given output size and intial count.
    /// 
    /// The final hash will be `FDH(M) = HASH(M||C) || HASH(M||C+1) || ... || HASH(M||C+N)`
    /// where `HASH` is any hash function, `M` is the message, `||` denotes concatenation, `C` is the initial_count, and `N` is the number of cycles requires for the output length.
    /// 
    /// If `initial_count` is large enough, it will "wrap around" from `xFF` to `x00` using modular addition.
    pub fn with_initial_count(output_size: usize, initial_count: u8) -> Result<Self, digest::InvalidOutputSize> {
        Ok(FullDomainHash {
            output_size,
            inner_hash: H::new(),
            initial_count
        })
    }

    /// Set the intial count on a FullDomainHash instance.
    /// 
    /// If `initial_count` is large enough, it will "wrap around" from `xFF` to `x00` using modular addition.
    pub fn set_initial_count(&mut self, initial_count: u8) {
        self.initial_count = initial_count;
    }
}

impl<H: Digest + Clone> VariableOutput for FullDomainHash<H> {

    /// Create new hasher instance with the given output size.
    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        FullDomainHash::with_initial_count(output_size, 0)
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

        let mut buf = Vec::<u8>::with_capacity(self.output_size);

        for i in 0..num_inner {
            let mut inner_hash = self.inner_hash.clone();

            // Append the final x00, x01, x02 etc.
            let append = self.initial_count.wrapping_add(i as u8);
            inner_hash.input([append]);
            buf.extend_from_slice(inner_hash.result().as_slice());
        }

        if remainder != 0 {
            let append = self.initial_count.wrapping_add(num_inner as u8);
            self.inner_hash.input([append]);
            buf.extend_from_slice(&self.inner_hash.result().as_slice()[..remainder]);
        }
        f(buf.as_slice());
    }
}

impl<H: Digest + Clone> Input for FullDomainHash<H> {

    /// Digest input data
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.inner_hash.input(data);
    }
}

impl<H: Digest + Clone> Reset for FullDomainHash<H> {

    /// Reset the hasher, discarding all internal state.
    fn reset(&mut self) {
        self.inner_hash.reset();
    }
}


#[cfg(test)]
mod tests {
    use sha2::Sha256;
    use hex;
    use crate::{FullDomainHash, VariableOutput, Input, Reset};

    #[test]
    fn sha256_test() {

        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(256 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f1");

        // Test Reset
        let mut hasher = FullDomainHash::<Sha256>::new(256 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        hasher.reset();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f1");

        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(128 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb283");


        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 && echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256
        let mut hasher = FullDomainHash::<Sha256>::new(264 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158");

        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits
        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x02' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x03' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::new(1024 / 8).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158617fec3b813f834cd86ab0dd26b971c46b7ede451b490279628a265edf0a10691095675808b47c0add4300b3181a31109cbc31a945d05562ceb6cca0fea834d9c456fe1abf34a5a775ed572ce571b1dcca03b984102e666e9ab876876fb3af");


        // # Expand SHA256 hash of "ATTACK AT DAWN" to 1024 bits, using 254 as the initial count.
        // echo -n -e 'ATTACK AT DAWN\xFE' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\xFF' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x00' | shasum -a 256 | cut -d ' ' -f 1 | tr -d '\n' &&\
        // echo -n -e 'ATTACK AT DAWN\x01' | shasum -a 256 | cut -d ' ' -f 1
        let mut hasher = FullDomainHash::<Sha256>::with_initial_count(1024 / 8, 254).unwrap();
        hasher.input(b"ATTACK AT DAWN");
        let result = hex::encode(hasher.vec_result());
        assert_eq!(result, "8b41c68cc83acfa422fb6a0c61c5c7a14eef381768d37375c78caf61d76e62b4a93a562946a7378fc3eca407eb44e81fef2be026e1ee340ba85a06f9b2e4fe84015d53c7925b4434f00286fe2f0eb28378a49300b159b896eb2356a7c4de95f158617fec3b813f834cd86ab0dd26b971c46b7ede451b490279628a265edf0a10");
    }
}
