pub use digest::{VariableOutput, Input, Reset};
use digest::Digest;

use num::bigint::BigUint;
use num::integer::Integer;
use num::traits::FromPrimitive;

#[derive(Clone)]
pub struct FullDomainHash<H: Digest> {
    output_size: usize,
    inner: Vec<H>,
    initial_count: u8,
}

impl<H: Digest> FullDomainHash<H> {
    pub fn with_initial_count(output_size: usize, initial_count: u8) -> Result<Self, digest::InvalidOutputSize> {
        let mut num_inner = output_size / H::output_size();

        // If our output size does not fit nicely into H::output_size(), 
        // then add an additional inner hash to fit the remainder.
        // When getting the result, this final inner will be truncated.
        if output_size % H::output_size() != 0 {
            num_inner += 1;
        }

        // Because we append a u8 to each message, maximum inner hashes is 256
        // This is 256 times the size of the orignal hash size
        if num_inner > 256 {
             return Err(digest::InvalidOutputSize);
        }

        let mut inner = Vec::with_capacity(num_inner);
        for _ in 0..num_inner {
            inner.push(H::new());
        }

        return Ok(FullDomainHash {
            output_size: output_size,
            inner: inner,
            initial_count: initial_count
        });
    }
}

impl<H: Digest> VariableOutput for FullDomainHash<H> {

    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        FullDomainHash::with_initial_count(output_size, 0)
    }

    fn output_size(&self) -> usize {
        return self.output_size;
    }

    fn variable_result<F: FnOnce(&[u8])>(mut self, f: F) {
        // Check if we need to truncate the final inner
        let truncate_final = self.output_size % H::output_size() != 0;
        let len = self.inner.len();

        let mut buf = Vec::<u8>::with_capacity(self.output_size);
        for (i, mut inner_hash) in self.inner.drain(..).enumerate() {

            // Append the final x00, x01, x02 etc.
            let append = i as u8 + self.initial_count;
            inner_hash.input([append]);

            // Trucate the final inner if things don't fit nicely.
            // This is equivilent to shifting out exessive bits.
            if truncate_final && i == (len -1) {
                let remainder = self.output_size % H::output_size();
                buf.extend_from_slice(&inner_hash.result().as_slice()[..remainder]);
            }
            else {
                buf.extend_from_slice(inner_hash.result().as_slice());
            }
        }
        f(buf.as_slice());
    }
}

impl<H: Digest> Input for FullDomainHash<H> {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        for inner_hash in self.inner.iter_mut() {
            inner_hash.input(data.as_ref().clone());
        }
    }
}

impl<H: Digest> Reset for FullDomainHash<H> {
    fn reset(&mut self) {
        let num_inner = self.output_size / H::output_size();
        let mut inner = Vec::with_capacity(num_inner);
        for _ in 0..num_inner {
            inner.push(H::new());
        }
        self.inner = inner;
    }
}

fn filtered_digest<H: Digest> (n: &BigUint) -> Vec<u8> {
    let c = 0;
    loop {
        // TODO: double-check we have a good sized n.
        let mut hasher = FullDomainHash::<H>::with_initial_count(n.bits() / 8, c).unwrap();
        hasher.input(n.to_bytes_be());
        let result = hasher.vec_result();
        let result_uint = BigUint::from_bytes_be(&result);
        if result_uint.gcd(n) == BigUint::from_i8(1).unwrap() {
            return result;
        }
    }
}


#[cfg(test)]
mod tests {
    use sha2::Sha256;
    use hex;
    use crate::{FullDomainHash, VariableOutput, Input, Reset};

    #[test]
    fn known_output() {

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
    }
}
