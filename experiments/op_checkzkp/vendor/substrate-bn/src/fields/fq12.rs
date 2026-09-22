use crate::fields::{const_fq, FieldElement, Fq, Fq2, Fq6};
use core::ops::{Add, Mul, Neg, Sub};
use rand::Rng;

fn frobenius_coeffs_c1(power: usize) -> Fq2 {
    match power % 12 {
        0 => Fq2::one(),
        1 => Fq2::new(
            const_fq([
                12653890742059813127,
                14585784200204367754,
                1278438861261381767,
                212598772761311868,
            ]),
            const_fq([
                11683091849979440498,
                14992204589386555739,
                15866167890766973222,
                1200023580730561873,
            ]),
        ),
        2 => Fq2::new(
            const_fq([
                14595462726357228530,
                17349508522658994025,
                1017833795229664280,
                299787779797702374,
            ]),
            Fq::zero(),
        ),
        3 => Fq2::new(
            const_fq([
                3914496794763385213,
                790120733010914719,
                7322192392869644725,
                581366264293887267,
            ]),
            const_fq([
                12817045492518885689,
                4440270538777280383,
                11178533038884588256,
                2767537931541304486,
            ]),
        ),
        _ => unimplemented!(),
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Fq12 {
    c0: Fq6,
    c1: Fq6,
}

impl Fq12 {
    pub fn new(c0: Fq6, c1: Fq6) -> Self {
        Fq12 { c0: c0, c1: c1 }
    }

    /// Canonical tower order: Fq12 c0,c1; Fq6 c0,c1,c2; Fq2 c0,c1.
    pub fn to_big_endian(&self, output: &mut [u8]) -> Option<()> {
        if output.len() != 384 {
            return None;
        }
        let coefficients = [
            &self.c0.c0,
            &self.c0.c1,
            &self.c0.c2,
            &self.c1.c0,
            &self.c1.c1,
            &self.c1.c2,
        ];
        for (coefficient, bytes) in coefficients.iter().zip(output.chunks_exact_mut(64)) {
            coefficient.to_big_endian(bytes)?;
        }
        Some(())
    }

    pub fn from_big_endian(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 384 {
            return None;
        }
        Some(Self::new(
            Fq6::new(
                Fq2::from_big_endian(&bytes[..64])?,
                Fq2::from_big_endian(&bytes[64..128])?,
                Fq2::from_big_endian(&bytes[128..192])?,
            ),
            Fq6::new(
                Fq2::from_big_endian(&bytes[192..256])?,
                Fq2::from_big_endian(&bytes[256..320])?,
                Fq2::from_big_endian(&bytes[320..])?,
            ),
        ))
    }

    fn final_exponentiation_first_chunk(&self) -> Option<Fq12> {
        match self.inverse() {
            Some(b) => {
                let a = self.unitary_inverse();
                let c = a * b;
                let d = c.frobenius_map(2);

                Some(d * c)
            }
            None => None,
        }
    }

    fn final_exponentiation_last_chunk(&self) -> Fq12 {
        let a = self.exp_by_neg_z();
        let b = a.cyclotomic_squared();
        let c = b.cyclotomic_squared();
        let d = c * b;

        let e = d.exp_by_neg_z();
        let f = e.cyclotomic_squared();
        let g = f.exp_by_neg_z();
        let h = d.unitary_inverse();
        let i = g.unitary_inverse();

        let j = i * e;
        let k = j * h;
        let l = k * b;
        let m = k * e;
        let n = *self * m;

        let o = l.frobenius_map(1);
        let p = o * n;

        let q = k.frobenius_map(2);
        let r = q * p;

        let s = self.unitary_inverse();
        let t = s * l;
        let u = t.frobenius_map(3);
        let v = u * r;

        v
    }

    pub fn final_exponentiation(&self) -> Option<Fq12> {
        self.final_exponentiation_first_chunk()
            .map(|a| a.final_exponentiation_last_chunk())
    }

    pub fn frobenius_map(&self, power: usize) -> Self {
        Fq12 {
            c0: self.c0.frobenius_map(power),
            c1: self
                .c1
                .frobenius_map(power)
                .scale(frobenius_coeffs_c1(power)),
        }
    }

    pub fn exp_by_neg_z(&self) -> Fq12 {
        // Adapted from gnark-crypto's BN254 Expt addition/subtraction chain:
        // https://github.com/Consensys/gnark-crypto/blob/master/ecc/bn254/internal/fptower/e12_pairing.go
        // Copyright 2020-2026 Consensys Software Inc.; Apache-2.0 (LICENSE-APACHE).
        // 60 cyclotomic squares, 17 multiplies, 5 conjugates for positive z.
        // Conjugation is inversion here because the input is cyclotomic.
        fn square_n(mut value: Fq12, count: usize) -> Fq12 {
            for _ in 0..count {
                value = value.cyclotomic_squared();
            }
            value
        }
        let x2 = self.cyclotomic_squared();
        let x3 = *self * x2;
        let x5 = x2 * x3;
        let x7 = x2 * x5;
        let mut result = square_n(*self * x7, 3) * x5;
        result = square_n(result, 5) * x3.unitary_inverse();
        result = square_n(result, 4) * x3;
        result = square_n(result, 5) * x5;
        result = square_n(result, 4) * x5.unitary_inverse();
        result = square_n(result, 4) * x3.unitary_inverse();
        result = square_n(result, 4) * *self;
        result = square_n(result, 5) * x5;
        result = square_n(result, 5) * x7;
        result = square_n(result, 4) * x7.unitary_inverse();
        result = square_n(result, 7) * x5;
        result = square_n(result, 5) * self.unitary_inverse();
        (square_n(result, 4) * *self).unitary_inverse()
    }

    pub fn unitary_inverse(&self) -> Fq12 {
        Fq12::new(self.c0, -self.c1)
    }

    pub fn mul_by_024(&self, ell_0: Fq2, ell_vw: Fq2, ell_vv: Fq2) -> Fq12 {
        let z0 = self.c0.c0;
        let z1 = self.c0.c1;
        let z2 = self.c0.c2;
        let z3 = self.c1.c0;
        let z4 = self.c1.c1;
        let z5 = self.c1.c2;

        let x0 = ell_0;
        let x2 = ell_vv;
        let x4 = ell_vw;

        let d0 = z0 * x0;
        let d2 = z2 * x2;
        let d4 = z4 * x4;
        let t2 = z0 + z4;
        let t1 = z0 + z2;
        let s0 = z1 + z3 + z5;

        let s1 = z1 * x2;
        let t3 = s1 + d4;
        let t4 = t3.mul_by_nonresidue() + d0;
        let z0 = t4;

        let t3 = z5 * x4;
        let s1 = s1 + t3;
        let t3 = t3 + d2;
        let t4 = t3.mul_by_nonresidue();
        let t3 = z1 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z1 = t4;

        let t0 = x0 + x2;
        let t3 = t1 * t0 - d0 - d2;
        let t4 = z3 * x4;
        let s1 = s1 + t4;
        let t3 = t3 + t4;

        let t0 = z2 + z4;
        let z2 = t3;

        let t1 = x2 + x4;
        let t3 = t0 * t1 - d2 - d4;
        let t4 = t3.mul_by_nonresidue();
        let t3 = z3 * x0;
        let s1 = s1 + t3;
        let t4 = t4 + t3;
        let z3 = t4;

        let t3 = z5 * x2;
        let s1 = s1 + t3;
        let t4 = t3.mul_by_nonresidue();
        let t0 = x0 + x4;
        let t3 = t2 * t0 - d0 - d4;
        let t4 = t4 + t3;
        let z4 = t4;

        let t0 = x0 + x2 + x4;
        let t3 = s0 * t0 - s1;
        let z5 = t3;

        Fq12 {
            c0: Fq6::new(z0, z1, z2),
            c1: Fq6::new(z3, z4, z5),
        }
    }

    /// Accumulate two sparse lines with 23 Fq2 products instead of 26.
    pub fn mul_by_024_pair(
        &self,
        a0: Fq2,
        avw: Fq2,
        avv: Fq2,
        b0: Fq2,
        bvw: Fq2,
        bvv: Fq2,
    ) -> Self {
        // The product has no c1.c2 coefficient in this tower ordering.
        let d0 = a0 * b0;
        let d2 = avv * bvv;
        let d4 = avw * bvw;
        let c0 = Fq6::new(
            d0 + d4.mul_by_nonresidue(),
            d2.mul_by_nonresidue(),
            (a0 + avv) * (b0 + bvv) - d0 - d2,
        );
        let c10 = ((avv + avw) * (bvv + bvw) - d2 - d4).mul_by_nonresidue();
        let c11 = (a0 + avw) * (b0 + bvw) - d0 - d4;

        // Multiply self.c1 by (c10, c11, 0) using five products.
        let t0 = self.c1.c0 * c10;
        let t1 = self.c1.c1 * c11;
        let bb = Fq6::new(
            t0 + (self.c1.c2 * c11).mul_by_nonresidue(),
            (self.c1.c0 + self.c1.c1) * (c10 + c11) - t0 - t1,
            self.c1.c2 * c10 + t1,
        );
        let aa = self.c0 * c0;
        Self::new(
            aa + bb.mul_by_nonresidue(),
            (self.c0 + self.c1) * Fq6::new(c0.c0 + c10, c0.c1 + c11, c0.c2) - aa - bb,
        )
    }

    pub fn cyclotomic_squared(&self) -> Self {
        let z0 = self.c0.c0;
        let z4 = self.c0.c1;
        let z3 = self.c0.c2;
        let z2 = self.c1.c0;
        let z1 = self.c1.c1;
        let z5 = self.c1.c2;

        let tmp = z0 * z1;
        let t0 = z0.squared() + z1.squared().mul_by_nonresidue();
        let t1 = tmp.doubled();

        let tmp = z2 * z3;
        let t2 = z2.squared() + z3.squared().mul_by_nonresidue();
        let t3 = tmp.doubled();

        let tmp = z4 * z5;
        let t4 = z4.squared() + z5.squared().mul_by_nonresidue();
        let t5 = tmp.doubled();

        let z0 = t0 - z0;
        let z0 = z0.doubled();
        let z0 = z0 + t0;

        let z1 = t1 + z1;
        let z1 = z1.doubled();
        let z1 = z1 + t1;

        let tmp = t5.mul_by_nonresidue();
        let z2 = tmp + z2;
        let z2 = z2.doubled();
        let z2 = z2 + tmp;

        let z3 = t4 - z3;
        let z3 = z3.doubled();
        let z3 = z3 + t4;

        let z4 = t2 - z4;
        let z4 = z4.doubled();
        let z4 = z4 + t2;

        let z5 = t3 + z5;
        let z5 = z5.doubled();
        let z5 = z5 + t3;

        Fq12 {
            c0: Fq6::new(z0, z4, z3),
            c1: Fq6::new(z2, z1, z5),
        }
    }
}

impl FieldElement for Fq12 {
    fn zero() -> Self {
        Fq12 {
            c0: Fq6::zero(),
            c1: Fq6::zero(),
        }
    }

    fn one() -> Self {
        Fq12 {
            c0: Fq6::one(),
            c1: Fq6::zero(),
        }
    }

    fn random<R: Rng>(rng: &mut R) -> Self {
        Fq12 {
            c0: Fq6::random(rng),
            c1: Fq6::random(rng),
        }
    }

    fn is_zero(&self) -> bool {
        self.c0.is_zero() && self.c1.is_zero()
    }

    fn squared(&self) -> Self {
        let ab = self.c0 * self.c1;

        Fq12 {
            c0: (self.c1.mul_by_nonresidue() + self.c0) * (self.c0 + self.c1)
                - ab
                - ab.mul_by_nonresidue(),
            c1: ab.doubled(),
        }
    }

    fn inverse(self) -> Option<Self> {
        match (self.c0.squared() - (self.c1.squared().mul_by_nonresidue())).inverse() {
            Some(t) => Some(Fq12 {
                c0: self.c0 * t,
                c1: -(self.c1 * t),
            }),
            None => None,
        }
    }
}

impl Mul for Fq12 {
    type Output = Fq12;

    fn mul(self, other: Fq12) -> Fq12 {
        let aa = self.c0 * other.c0;
        let bb = self.c1 * other.c1;

        Fq12 {
            c0: bb.mul_by_nonresidue() + aa,
            c1: (self.c0 + self.c1) * (other.c0 + other.c1) - aa - bb,
        }
    }
}

impl Sub for Fq12 {
    type Output = Fq12;

    fn sub(self, other: Fq12) -> Fq12 {
        Fq12 {
            c0: self.c0 - other.c0,
            c1: self.c1 - other.c1,
        }
    }
}

impl Add for Fq12 {
    type Output = Fq12;

    fn add(self, other: Fq12) -> Fq12 {
        Fq12 {
            c0: self.c0 + other.c0,
            c1: self.c1 + other.c1,
        }
    }
}

impl Neg for Fq12 {
    type Output = Fq12;

    fn neg(self) -> Fq12 {
        Fq12 {
            c0: -self.c0,
            c1: -self.c1,
        }
    }
}

#[test]
fn canonical_encoding_uses_explicit_tower_order() {
    use crate::arith::U256;
    let coordinate = |value: u64| Fq::new(U256::from(value)).unwrap();
    let value = Fq12::new(
        Fq6::new(
            Fq2::new(coordinate(1), coordinate(2)),
            Fq2::new(coordinate(3), coordinate(4)),
            Fq2::new(coordinate(5), coordinate(6)),
        ),
        Fq6::new(
            Fq2::new(coordinate(7), coordinate(8)),
            Fq2::new(coordinate(9), coordinate(10)),
            Fq2::new(coordinate(11), coordinate(12)),
        ),
    );
    let mut expected = [0u8; 384];
    for index in 0..12 {
        expected[index * 32 + 31] = index as u8 + 1;
    }
    let mut encoded = [0u8; 384];
    value.to_big_endian(&mut encoded).unwrap();
    assert_eq!(encoded, expected);
    assert_eq!(Fq12::from_big_endian(&expected), Some(value));
}

#[test]
fn paired_sparse_lines_match_dense_products() {
    use rand::{rngs::StdRng, SeedableRng};
    let mut rng = StdRng::from_seed([37; 32]);
    let line = |a: [Fq2; 3]| {
        Fq12::new(
            Fq6::new(a[0], Fq2::zero(), a[2]),
            Fq6::new(Fq2::zero(), a[1], Fq2::zero()),
        )
    };
    for index in 0..64 {
        let f = if index == 0 { Fq12::zero() } else { Fq12::random(&mut rng) };
        let mut a = [Fq2::random(&mut rng), Fq2::random(&mut rng), Fq2::random(&mut rng)];
        let mut b = [Fq2::random(&mut rng), Fq2::random(&mut rng), Fq2::random(&mut rng)];
        if index < 3 {
            a = [Fq2::zero(); 3];
            a[index] = Fq2::one();
        }
        if index == 3 {
            b = [Fq2::zero(); 3];
        }
        assert_eq!(
            f.mul_by_024_pair(a[0], a[1], a[2], b[0], b[1], b[2]),
            f * line(a) * line(b),
        );
    }
}
