use bitvec::order::Msb0;
use bitvec::vec::*;
use digest::{ExtendableOutput, Input, XofReader};
use num_bigint::BigUint;
use std::vec;
use std::vec::Vec;
use subtle::Choice;

pub struct MWFDH<H, C>
where
    H: ExtendableOutput + Input + Default + Clone,
    C: Fn(&[u8]) -> Choice,
{
    iterations: usize,
    output_size: usize,
    inner_hash: H,
    domain_function: C,
}

impl<H, C> MWFDH<H, C>
where
    H: ExtendableOutput + Input + Default + Clone,
    C: Fn(&[u8]) -> Choice,
{
    pub fn new(iterations: usize, output_size: usize, domain_function: C) -> Self {
        if iterations % 8 != 0 {
            panic!("fdh-rs: movingwindow: iterations must be multiple of 8");
        }

        MWFDH {
            iterations: iterations,
            output_size: output_size,
            inner_hash: H::default(),
            domain_function: domain_function,
        }
    }

    pub fn input(&mut self, input: &[u8]) {
        self.inner_hash.input(input);
    }

    /// Get a digest value that is within the domain specified by the passed closure.
    ///
    /// # Example
    /// ```rust
    /// use sha2::Sha512;
    /// use fdh::{FullDomainHash, Input, VariableOutput};
    /// use num_bigint::BigUint;
    /// use num_integer::Integer;
    ///
    /// // Get a full domain hash that is odd
    /// let mut hasher = FullDomainHash::<Sha512>::new(64).unwrap();
    /// hasher.input(b"ATTACKATDAWN");
    ///
    /// let (digest, iv) = hasher.results_in_domain(0, |digest| BigUint::from_bytes_be(digest).is_odd()).unwrap();
    /// ```
    pub fn results_in_domain(&self) -> Result<Vec<u8>, ()> {
        let mut all_candidates = self.all_candidates();

        let mut selection: usize = 0;
        let mut in_domain: Choice = 0.into();
        for candidate in all_candidates.iter() {
            in_domain |= (self.domain_function)(candidate);
            if in_domain.into() {
                selection += 0;
            } else {
                selection += 1;
            }
        }

        let found_domain: bool = in_domain.into();
        if (!found_domain) {
            return Err(());
        }

        let result: Vec<u8> = all_candidates.remove(selection);
        Ok(result)
    }

    fn all_candidates(&self) -> Vec<Vec<u8>> {
        let inner_hash = self.inner_hash.clone();
        let mut reader = inner_hash.xof_result();
        let underlying_size = self.output_size * (self.iterations / 8);
        let mut result: Vec<u8> = vec![0x00; underlying_size];
        reader.read(&mut result);

        compute_candidates(result, self.output_size, self.iterations)
    }
}

// Given a Vec<u8> (as you would get from an underlying digest),
// get a Vec of all moving windows applied against that input
fn compute_candidates(
    input: Vec<u8>,
    moving_window_size: usize,
    num_iterations: usize,
) -> Vec<Vec<u8>> {
    // TODO: debug assert input.len(), moving_window_size, and num_iterations all line up
    let mut underlying_digest: BitVec<Msb0, u8> = input.into();
    let mut all_candidates = Vec::<Vec<u8>>::with_capacity(num_iterations);

    for _ in 0..num_iterations {
        let u8_view = underlying_digest.as_slice();
        all_candidates.push(u8_view[0..moving_window_size].iter().cloned().collect());
        underlying_digest = underlying_digest << 1;
    }

    all_candidates
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

fn between(check: &[u8], min: &BigUint, max: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    ((&check < max && &check > min) as u8).into()
}

fn lt(check: &[u8], max: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    ((&check < max) as u8).into()
}

fn gt(check: &[u8], min: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    ((&check > min) as u8).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use num_traits::Num;
    use sha3::Shake128;
    use std::dbg;

    #[test]
    fn all_candidates_test() {
        let some_vec = vec![0, 0, 0, 0, 0, 255];
        let candidates = compute_candidates(some_vec, 5, 8);

        assert_eq!(candidates[0], vec![0, 0, 0, 0, 0]);
        assert_eq!(candidates[7], vec![0, 0, 0, 0, 127]);
        // IF we had shifted one more we would have [0, 0, 0, 0, 255]
    }

    #[test]
    fn test_results_within() {
        use num_bigint::BigUint;
        use num_traits::Num;

        let min = BigUint::from_str_radix(
            "51683095453715361952842063988888814558178328011011413557662527675023521115731",
            10,
        )
        .unwrap();
        let max = BigUint::from_str_radix(
            "63372381656167118369940880608146415619543459354936568979731399163319071519847",
            10,
        )
        .unwrap();

        let mut hasher = MWFDH::<Shake128, _>::new(128, 32, |check: _| between(check, &min, &max));

        hasher.input(b"ATTACK AT DAWN");
        let result = hasher.results_in_domain().unwrap();
        assert_eq!(
            hex::encode(result),
            "7ebe111e3d443145d87f7b574f67f92be291f19d747a489601e40bd6f3671008"
        );
    }
}
