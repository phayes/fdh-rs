use bitvec::*;
use digest::{ExtendableOutput, Input, XofReader};
use std::vec;
use std::vec::Vec;

pub struct MWFullDomainHash<H: ExtendableOutput + Input + Default> {
    output_size: usize,
    inner_hash: H,
}

impl<H: ExtendableOutput + Input + Default> MWFullDomainHash<H> {
    pub fn new(output_size: usize) -> Self {
        MWFullDomainHash {
            output_size: output_size,
            inner_hash: H::default(),
        }
    }

    pub fn input(&mut self, input: &[u8]) {
        self.inner_hash.input(input);
    }

    pub fn result_below(self, max: &[u8]) -> Vec<u8> {
        let max = left_pad(max, self.output_size); // TODO: Can we skip this in the commong case when lengths match?

        let mut reader = self.inner_hash.xof_result();
        let mut result: Vec<u8> = vec![0x00; self.output_size];
        reader.read(&mut result);

        if &result as &[u8] < &max {
            // Happy path
            return result.into();
        } else {
            let mut result: BitVec<bitvec::BigEndian, u8> = result.into();
            let mut read_buf = BitVec::<bitvec::BigEndian, u8>::with_capacity(8);
            let max: BitVec<bitvec::BigEndian, u8> = max.into();
            let mut read_buf_pos = 0;
            while result > max {
                if read_buf_pos == 0 {
                    let mut temp_buf: Vec<u8> = vec![0x00];
                    reader.read(&mut temp_buf);
                    read_buf = temp_buf.into();
                }
                result = result << 1;
                result.push(read_buf[read_buf_pos]);

                read_buf_pos += 1;
                if read_buf_pos == 8 {
                    read_buf_pos = 0;
                }
            }
            result.into()
        }
    }
}

fn left_pad(input: &[u8], size: usize) -> std::vec::Vec<u8> {
    let n = if input.len() > size {
        size
    } else {
        input.len()
    };

    let mut out = std::vec![0u8; size];
    out[size - n..].copy_from_slice(input);
    out
}

#[cfg(test)]
mod tests {
    use crate::movingwindow::MWFullDomainHash;
    use num_bigint::BigUint;
    use num_traits::Num;
    use sha3::Shake128;

    #[test]
    fn bit_test() {
        let max = BigUint::from_str_radix(
            "00523095453715361952842063988888814558178328011011413557662527675023521115731",
            10,
        )
        .unwrap();

        let mut mwfdh = MWFullDomainHash::<Shake128>::new(256 / 8);
        mwfdh.input(b"ATTACK AT DAWN");
        let _result = mwfdh.result_below(&max.to_bytes_be());
    }

}
