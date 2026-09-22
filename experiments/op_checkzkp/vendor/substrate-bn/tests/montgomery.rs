use num_bigint::BigUint;
use substrate_bn::arith::U256;

fn encoded(value: &BigUint) -> U256 {
    let bytes = value.to_bytes_be();
    let mut fixed = [0u8; 32];
    fixed[32 - bytes.len()..].copy_from_slice(&bytes);
    U256::from_slice(&fixed).unwrap()
}

fn integer(value: &U256) -> BigUint {
    let mut bytes = [0u8; 32];
    value.to_big_endian(&mut bytes).unwrap();
    BigUint::from_bytes_be(&bytes)
}

#[test]
fn montgomery_carries_match_independent_integer_arithmetic() {
    let moduli = [
        (
            U256::from([
                0x3c208c16d87cfd47,
                0x97816a916871ca8d,
                0xb85045b68181585d,
                0x30644e72e131a029,
            ]),
            0x09ede7d651eca6ac987d20782e4866389u128,
        ),
        (
            U256::from([
                0x43e1f593f0000001,
                0x2833e84879b97091,
                0xb85045b68181585d,
                0x30644e72e131a029,
            ]),
            0x6586864b4c6911b3c2e1f593efffffffu128,
        ),
    ];
    let radix = BigUint::from(1u32) << 256usize;
    // Public deterministic test data, not cryptographic randomness.
    let mut state = 0x6761735f63617272u64;
    for (modulus, inv) in moduli {
        let p = integer(&modulus);
        let r_inverse = radix.modpow(&(&p - 2u32), &p);
        let mut values = vec![
            BigUint::from(0u32),
            BigUint::from(1u32),
            &p - 1u32,
            p.clone(),
            &p + 1u32,
            &radix - 1u32,
        ];
        for bits in (32..=256).step_by(32) {
            values.push((BigUint::from(1u32) << bits) - 1u32);
        }
        for _ in 0..128 {
            let mut bytes = [0u8; 32];
            for chunk in bytes.chunks_exact_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes());
            }
            values.push(BigUint::from_bytes_le(&bytes));
        }
        // Covers zero, maximal limbs, cross-limb carries, reduction boundaries,
        // and the unreduced input supported by Fr::new_mul_factor. Check both
        // operand orders: it is sufficient for either input to be reduced.
        for a in &values {
            for raw_b in &values {
                let b = raw_b % &p;
                let expected = (a * &b * &r_inverse) % &p;
                let mut product = encoded(a);
                product.mul(&encoded(&b), &modulus, inv);
                assert_eq!(integer(&product), expected);
                let mut reverse = encoded(&b);
                reverse.mul(&encoded(a), &modulus, inv);
                assert_eq!(integer(&reverse), expected);
            }
        }
    }
}
