use substrate_bn::{arith::U256, Fr, Group, G1};

fn scalar(value: u128) -> Fr {
    Fr::new(U256([value, 0])).unwrap()
}

#[test]
fn interleaved_msm_matches_binary_multiplication_at_boundaries() {
    let g = G1::one();
    let points = [g, -g, g * scalar(2), g * scalar(3)];
    let values = [
        1u128 << 127,
        u128::MAX,
        (1u128 << 64) + 1,
        (1u128 << 32) - 1,
    ];
    let terms = core::array::from_fn(|i| (points[i], values[i]));
    let expected = terms.iter().fold(G1::zero(), |sum, (point, value)| {
        sum + *point * scalar(*value)
    });
    assert_eq!(G1::msm_128(&terms), expected);
    assert_eq!(G1::msm_128(&points.map(|p| (p, 0))), G1::zero());
}

#[test]
fn interleaved_msm_accepts_infinity_from_subset_cancellation() {
    let g = G1::one();
    let doubled = g + g;
    let terms = [
        (g, u128::MAX),
        (-g, u128::MAX),
        (doubled, 1u128 << 127),
        (-doubled, 1u128 << 127),
    ];
    assert_eq!(G1::msm_128(&terms), G1::zero());
    let zero_terms = [(g, u128::MAX), (-g, u128::MAX), (G1::zero(), 19), (g, 0)];
    assert_eq!(G1::msm_128(&zero_terms), G1::zero());
}
