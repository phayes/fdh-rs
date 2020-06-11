use digest::{ExtendableOutput, Update, XofReader};
use num_bigint::BigUint;
use std::vec;
use std::vec::Vec;
use subtle::Choice;
use subtle::ConditionallySelectable;

pub struct MWFDH<H, C>
where
    H: ExtendableOutput + Update + Default + Clone,
    C: Fn(&[u8]) -> Choice,
{
    iterations: usize,
    output_size: usize,
    domain_function: C,
    inner_hash: H,
}

impl<H, C> MWFDH<H, C>
where
    H: ExtendableOutput + Update + Default + Clone,
    C: Fn(&[u8]) -> Choice,
{
    pub fn new(iterations: usize, output_size: usize, domain_function: C) -> Self {
        MWFDH {
            iterations,
            output_size,
            domain_function,
            inner_hash: H::default(),
        }
    }

    pub fn input(&mut self, input: &[u8]) {
        self.inner_hash.update(input);
    }

    pub fn results_in_domain(&self) -> Result<Vec<u8>, ()> {
        let mut all_candidates = self.all_candidates();

        let mut selection: u32 = 0;
        let mut in_domain: Choice = 0.into();
        for candidate in all_candidates.iter() {
            in_domain |= (self.domain_function)(candidate);
            let selection_plus_one = selection + 1;
            selection.conditional_assign(&selection_plus_one, !in_domain);
        }

        let found_domain: bool = in_domain.into();
        if !found_domain {
            return Err(());
        }

        // TODO: Check if this is constant-time,
        let result: Vec<u8> = all_candidates.remove(selection as usize);
        Ok(result)
    }

    fn all_candidates(&self) -> Vec<Vec<u8>> {
        let inner_hash = self.inner_hash.clone();
        let mut reader = inner_hash.finalize_xof();
        let underlying_size = self.output_size * (self.iterations);
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
    let mut all_candidates = Vec::<Vec<u8>>::with_capacity(num_iterations);

    for i in 0..num_iterations {
        all_candidates.push(input[i..moving_window_size + i].iter().cloned().collect());
    }

    all_candidates
}

// TODO: This is unsafe - move to using secret_integers crate
pub fn between(check: &[u8], min: &BigUint, max: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    Choice::from((&check < max) as u8) & Choice::from((&check > min) as u8)
}

// TODO: This is unsafe - move to using secret_integers crate
pub fn lt(check: &[u8], max: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    ((&check < max) as u8).into()
}

// TODO: This is unsafe - move to using secret_integers crate
pub fn gt(check: &[u8], min: &BigUint) -> Choice {
    let check = BigUint::from_bytes_be(check);
    ((&check > min) as u8).into()
}

// WIP for moving to secret_integers
//pub fn gt(input: &[u8], min: &[u8]) -> Choice {
//    let shorter_than_min = Choice::from((input.len() < min.len()) as u8);
//
//   let mut gt = Choice::from(0);
//    for (&ai, &bi) in input.iter().zip(min.iter()) {
//        let ai = U8::classify(ai);
//        let bi = U8::classify(bi);
//
//        let greater = ai.comp_gt(bi);
//        if ai.comp_gt(bi) {
//            return Greater;
//        }
//    }
//
//    let check = BigUint::from_bytes_be(check);
//    ((&check > min) as u8).into()
//}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::Shake128;

    #[test]
    fn all_candidates_test() {
        let input = vec![0, 1, 2, 3, 4, 5, 6, 7];
        let candidates = compute_candidates(input, 5, 4);

        assert_eq!(candidates[0], vec![0, 1, 2, 3, 4]);
        assert_eq!(candidates[1], vec![1, 2, 3, 4, 5]);
        assert_eq!(candidates[2], vec![2, 3, 4, 5, 6]);
        assert_eq!(candidates[3], vec![3, 4, 5, 6, 7]);
    }

    #[test]
    fn test_results_between() {
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

        let mut hasher = MWFDH::<Shake128, _>::new(2048, 32, |check: _| between(check, &min, &max));

        hasher.input(b"ATTACK AT DAWN");
        let result = hasher.results_in_domain().unwrap();

        assert_eq!(
            hex::encode(&result),
            "7ebe111e3d443145d87f7b574f67f92be291f19d747a489601e40bd6f3671008"
        );

        let result_bigint = BigUint::from_bytes_be(&result).to_str_radix(10);
        assert_eq!(
            result_bigint,
            "57327238008737855959412403183414616474281863704162301159073898079241428733960"
        );
    }

    #[test]
    fn test_results_lt() {
        use num_bigint::BigUint;
        use num_traits::Num;

        let max = BigUint::from_str_radix(
            "23372381656167118369940880608146415619543459354936568979731399163319071519847",
            10,
        )
        .unwrap();

        let mut hasher = MWFDH::<Shake128, _>::new(2048, 32, |check: _| lt(check, &max));

        hasher.input(b"ATTACK AT DAWN");
        let result = hasher.results_in_domain().unwrap();
        assert_eq!(
            hex::encode(&result),
            "111e3d443145d87f7b574f67f92be291f19d747a489601e40bd6f36710080831"
        );

        let result_bigint = BigUint::from_bytes_be(&result).to_str_radix(10);
        assert_eq!(
            result_bigint,
            "7742746682851442867075436372447051338297254606827936826213800416869211441201"
        );
    }

    #[test]
    fn test_results_gt() {
        use num_bigint::BigUint;
        use num_traits::Num;

        let min = BigUint::from_str_radix(
            "81683095453715361952842063988888814558178328011011413557662527675023521115731",
            10,
        )
        .unwrap();

        let mut hasher = MWFDH::<Shake128, _>::new(2048, 32, |check: _| gt(check, &min));

        hasher.input(b"ATTACK AT DAWN");
        let result = hasher.results_in_domain().unwrap();
        assert_eq!(
            hex::encode(&result),
            "be111e3d443145d87f7b574f67f92be291f19d747a489601e40bd6f367100808"
        );

        let result_bigint = BigUint::from_bytes_be(&result).to_str_radix(10);
        assert_eq!(
            result_bigint,
            "85969686335050502239631103859465427904139040394838027751262323288751421261832"
        );
    }
}
