use substrate_bn::{
    arith::U256, pairing_batch, AffineG2, Fq, Fq2, Fr, Group, GroupError, Gt, PreparedPairing, G1,
    G2, PREPARED_PAIRING_BYTES,
};

fn scalar(value: u64) -> Fr {
    Fr::new(U256::from(value)).unwrap()
}

fn fixed_key() -> (G1, G2, G2, G2) {
    (
        G1::one() * scalar(2),
        G2::one() * scalar(3),
        G2::one() * scalar(5),
        G2::one() * scalar(7),
    )
}

fn encode(prepared: &PreparedPairing) -> Vec<u8> {
    let mut bytes = vec![0; PREPARED_PAIRING_BYTES];
    prepared.encode(&mut bytes).unwrap();
    bytes
}

#[test]
fn prepared_equation_matches_raw_pairing_with_and_without_ic() {
    let (alpha, beta, gamma, delta) = fixed_key();
    let prepared = PreparedPairing::prepare(alpha, beta, gamma, delta).unwrap();
    let bytes = encode(&prepared);
    let decoded = PreparedPairing::decode_committed(&bytes).unwrap();
    assert_eq!(encode(&decoded), bytes);

    let b_scalar = scalar(17);
    let b = G2::one() * b_scalar;
    let c_scalar = scalar(11);
    let c = G1::one() * c_scalar;
    for ic_scalar in [scalar(13), Fr::zero()] {
        let ic = G1::one() * ic_scalar;
        let a_scalar = (scalar(2) * scalar(3) + ic_scalar * scalar(5) + c_scalar * scalar(7))
            * b_scalar.inverse().unwrap();
        let valid_a = G1::one() * a_scalar;
        for (a, expected) in [(valid_a, true), (valid_a + G1::one(), false)] {
            let raw =
                pairing_batch(&[(a, b), (-alpha, beta), (-ic, gamma), (-c, delta)]) == Gt::one();
            assert_eq!(raw, expected);
            assert_eq!(prepared.verify(a, b, c, ic), Some(raw));
            assert_eq!(decoded.verify(a, b, c, ic), Some(raw));
        }
    }
}

#[test]
fn codec_rejects_wrong_lengths_noncanonical_fields_and_zero_target() {
    let (alpha, beta, gamma, delta) = fixed_key();
    let prepared = PreparedPairing::prepare(alpha, beta, gamma, delta).unwrap();
    let bytes = encode(&prepared);
    assert_eq!(bytes.len(), 33792);

    let mut short = bytes[..bytes.len() - 1].to_vec();
    assert!(prepared.encode(&mut short).is_none());
    assert!(PreparedPairing::decode_committed(&short).is_none());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(prepared.encode(&mut trailing).is_none());
    assert!(PreparedPairing::decode_committed(&trailing).is_none());

    // Check canonical decoding in the target and both fixed tables, including
    // the final coordinate so a decoder cannot silently ignore a table suffix.
    for offset in [0, 384, PREPARED_PAIRING_BYTES - 32] {
        let mut invalid = bytes.clone();
        Fq::modulus()
            .to_big_endian(&mut invalid[offset..offset + 32])
            .unwrap();
        assert!(PreparedPairing::decode_committed(&invalid).is_none());
    }
    let mut zero_target = bytes;
    zero_target[..384].fill(0);
    assert!(PreparedPairing::decode_committed(&zero_target).is_none());
}

#[test]
fn structurally_valid_zero_lines_fail_without_trapping_and_infinity_skips_gamma() {
    let (alpha, beta, gamma, delta) = fixed_key();
    let prepared = PreparedPairing::prepare(alpha, beta, gamma, delta).unwrap();
    let mut bytes = encode(&prepared);
    let delta_start = 384 + 87 * 192;
    bytes[384..delta_start].fill(0);
    // Structural decoding intentionally cannot authenticate the producer's
    // derivation. Malformed committed lines must still fail safely at runtime.
    let zero_gamma = PreparedPairing::decode_committed(&bytes).unwrap();
    let b = G2::one() * scalar(17);
    let c = G1::one() * scalar(11);
    let a = G1::one() * (scalar(83) * scalar(17).inverse().unwrap());
    assert_eq!(zero_gamma.verify(a, b, c, G1::one()), None);
    assert_eq!(zero_gamma.verify(a, b, c, G1::zero()), Some(true));

    bytes[delta_start..].fill(0);
    let zero_delta = PreparedPairing::decode_committed(&bytes).unwrap();
    assert_eq!(zero_delta.verify(a, b, c, G1::zero()), None);
}

#[test]
fn preparation_revalidates_every_source_point() {
    let (alpha, beta, gamma, delta) = fixed_key();
    let off_curve_g1 = G1::new(Fq::zero(), Fq::zero(), Fq::one());
    for invalid in [G1::zero(), off_curve_g1] {
        assert!(PreparedPairing::prepare(invalid, beta, gamma, delta).is_none());
    }

    // Public deterministic curve samples, not a setup seed. Construct through
    // unchecked Jacobian coordinates to exercise prepare's own subgroup check.
    let non_subgroup = (0..64u64)
        .find_map(|value| {
            let x = Fq2::new(Fq::from_u256(U256::from(value)).unwrap(), Fq::one());
            let y = (x * x * x + G2::b()).sqrt()?;
            match AffineG2::new(x, y) {
                Err(GroupError::NotInSubgroup) => Some(G2::new(x, y, Fq2::one())),
                _ => None,
            }
        })
        .expect("public curve sample outside G2 subgroup");
    let off_curve_g2 = G2::new(Fq2::zero(), Fq2::zero(), Fq2::one());
    for invalid in [G2::zero(), off_curve_g2, non_subgroup] {
        assert!(PreparedPairing::prepare(alpha, invalid, gamma, delta).is_none());
        assert!(PreparedPairing::prepare(alpha, beta, invalid, delta).is_none());
        assert!(PreparedPairing::prepare(alpha, beta, gamma, invalid).is_none());
    }
}
