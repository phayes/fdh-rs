pub use digest::{VariableOutput, Input, Reset};
use digest::Digest;

#[derive(Clone)]
pub struct FullDomainHash<H: Digest> {
    output_size: usize,
    inner_hash: H,
    initial_count: u8,
}

impl<H: Digest + Clone> FullDomainHash<H> {
    pub fn with_initial_count(output_size: usize, initial_count: u8) -> Result<Self, digest::InvalidOutputSize> {
        return Ok(FullDomainHash {
            output_size: output_size,
            inner_hash: H::new(),
            initial_count: initial_count
        });
    }
}

impl<H: Digest + Clone> VariableOutput for FullDomainHash<H> {

    fn new(output_size: usize) -> Result<Self, digest::InvalidOutputSize> {
        FullDomainHash::with_initial_count(output_size, 0)
    }

    fn output_size(&self) -> usize {
        return self.output_size;
    }

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
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.inner_hash.input(data);
    }
}

impl<H: Digest + Clone> Reset for FullDomainHash<H> {
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
