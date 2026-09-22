#![no_std]

extern crate alloc;

pub mod arith;
mod fields;
mod groups;

use crate::fields::FieldElement;
use crate::groups::{G1Params, G2Params, GroupElement, GroupParams};

use alloc::vec::Vec;
use core::ops::{Add, Mul, Neg, Sub};
use rand::Rng;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Fr(fields::Fr);

impl Fr {
    pub fn zero() -> Self {
        Fr(fields::Fr::zero())
    }
    pub fn one() -> Self {
        Fr(fields::Fr::one())
    }
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Fr(fields::Fr::random(rng))
    }
    pub fn pow(&self, exp: Fr) -> Self {
        Fr(self.0.pow(exp.0))
    }
    pub fn from_str(s: &str) -> Option<Self> {
        fields::Fr::from_str(s).map(|e| Fr(e))
    }
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(|e| Fr(e))
    }
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    pub fn interpret(buf: &[u8; 64]) -> Fr {
        Fr(fields::Fr::interpret(buf))
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self, FieldError> {
        arith::U256::from_slice(slice)
            .map_err(|_| FieldError::InvalidSliceLength) // todo: maybe more sensful error handling
            .map(|x| Fr::new_mul_factor(x))
    }
    pub fn to_big_endian(&self, slice: &mut [u8]) -> Result<(), FieldError> {
        self.0
            .raw()
            .to_big_endian(slice)
            .map_err(|_| FieldError::InvalidSliceLength)
    }
    pub fn new(val: arith::U256) -> Option<Self> {
        fields::Fr::new(val).map(|x| Fr(x))
    }
    pub fn new_mul_factor(val: arith::U256) -> Self {
        Fr(fields::Fr::new_mul_factor(val))
    }
    pub fn into_u256(self) -> arith::U256 {
        (self.0).into()
    }
    pub fn set_bit(&mut self, bit: usize, to: bool) {
        self.0.set_bit(bit, to);
    }
}

impl Add<Fr> for Fr {
    type Output = Fr;

    fn add(self, other: Fr) -> Fr {
        Fr(self.0 + other.0)
    }
}

impl Sub<Fr> for Fr {
    type Output = Fr;

    fn sub(self, other: Fr) -> Fr {
        Fr(self.0 - other.0)
    }
}

impl Neg for Fr {
    type Output = Fr;

    fn neg(self) -> Fr {
        Fr(-self.0)
    }
}

impl Mul for Fr {
    type Output = Fr;

    fn mul(self, other: Fr) -> Fr {
        Fr(self.0 * other.0)
    }
}

#[derive(Debug)]
pub enum FieldError {
    InvalidSliceLength,
    InvalidU512Encoding,
    NotMember,
}

#[derive(Debug)]
pub enum CurveError {
    InvalidEncoding,
    NotMember,
    Field(FieldError),
    ToAffineConversion,
}

impl From<FieldError> for CurveError {
    fn from(fe: FieldError) -> Self {
        CurveError::Field(fe)
    }
}

pub use crate::groups::Error as GroupError;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Fq(fields::Fq);

impl Fq {
    pub fn zero() -> Self {
        Fq(fields::Fq::zero())
    }
    pub fn one() -> Self {
        Fq(fields::Fq::one())
    }
    pub fn random<R: Rng>(rng: &mut R) -> Self {
        Fq(fields::Fq::random(rng))
    }
    pub fn pow(&self, exp: Fq) -> Self {
        Fq(self.0.pow(exp.0))
    }
    pub fn from_str(s: &str) -> Option<Self> {
        fields::Fq::from_str(s).map(|e| Fq(e))
    }
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(|e| Fq(e))
    }
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    pub fn interpret(buf: &[u8; 64]) -> Fq {
        Fq(fields::Fq::interpret(buf))
    }
    pub fn from_slice(slice: &[u8]) -> Result<Self, FieldError> {
        arith::U256::from_slice(slice)
            .map_err(|_| FieldError::InvalidSliceLength) // todo: maybe more sensful error handling
            .and_then(|x| fields::Fq::new(x).ok_or(FieldError::NotMember))
            .map(|x| Fq(x))
    }
    pub fn to_big_endian(&self, slice: &mut [u8]) -> Result<(), FieldError> {
        let mut a: arith::U256 = self.0.into();
        // convert from Montgomery representation
        a.mul(
            &fields::Fq::one().raw(),
            &fields::Fq::modulus(),
            self.0.inv(),
        );
        a.to_big_endian(slice)
            .map_err(|_| FieldError::InvalidSliceLength)
    }
    pub fn from_u256(u256: arith::U256) -> Result<Self, FieldError> {
        Ok(Fq(fields::Fq::new(u256).ok_or(FieldError::NotMember)?))
    }
    pub fn into_u256(self) -> arith::U256 {
        (self.0).into()
    }
    pub fn modulus() -> arith::U256 {
        fields::Fq::modulus()
    }

    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(Fq)
    }
}

impl Add<Fq> for Fq {
    type Output = Fq;

    fn add(self, other: Fq) -> Fq {
        Fq(self.0 + other.0)
    }
}

impl Sub<Fq> for Fq {
    type Output = Fq;

    fn sub(self, other: Fq) -> Fq {
        Fq(self.0 - other.0)
    }
}

impl Neg for Fq {
    type Output = Fq;

    fn neg(self) -> Fq {
        Fq(-self.0)
    }
}

impl Mul for Fq {
    type Output = Fq;

    fn mul(self, other: Fq) -> Fq {
        Fq(self.0 * other.0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Fq2(fields::Fq2);

impl Fq2 {
    pub fn one() -> Fq2 {
        Fq2(fields::Fq2::one())
    }

    pub fn i() -> Fq2 {
        Fq2(fields::Fq2::i())
    }

    pub fn zero() -> Fq2 {
        Fq2(fields::Fq2::zero())
    }

    /// Initalizes new F_q2(a + bi, a is real coeff, b is imaginary)
    pub fn new(a: Fq, b: Fq) -> Fq2 {
        Fq2(fields::Fq2::new(a.0, b.0))
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub fn pow(&self, exp: arith::U256) -> Self {
        Fq2(self.0.pow(exp))
    }

    pub fn real(&self) -> Fq {
        Fq(*self.0.real())
    }

    pub fn imaginary(&self) -> Fq {
        Fq(*self.0.imaginary())
    }

    pub fn sqrt(&self) -> Option<Self> {
        self.0.sqrt().map(Fq2)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, FieldError> {
        let u512 = arith::U512::from_slice(bytes).map_err(|_| FieldError::InvalidU512Encoding)?;
        let (res, c0) = u512.divrem(&Fq::modulus());
        Ok(Fq2::new(
            Fq::from_u256(c0).map_err(|_| FieldError::NotMember)?,
            Fq::from_u256(res.ok_or(FieldError::NotMember)?).map_err(|_| FieldError::NotMember)?,
        ))
    }
}

impl Add<Fq2> for Fq2 {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Fq2(self.0 + other.0)
    }
}

impl Sub<Fq2> for Fq2 {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        Fq2(self.0 - other.0)
    }
}

impl Neg for Fq2 {
    type Output = Self;

    fn neg(self) -> Self {
        Fq2(-self.0)
    }
}

impl Mul for Fq2 {
    type Output = Self;

    fn mul(self, other: Self) -> Self {
        Fq2(self.0 * other.0)
    }
}

pub trait Group:
    Send
    + Sync
    + Copy
    + Clone
    + PartialEq
    + Eq
    + Sized
    + Add<Self, Output = Self>
    + Sub<Self, Output = Self>
    + Neg<Output = Self>
    + Mul<Fr, Output = Self>
{
    fn zero() -> Self;
    fn one() -> Self;
    fn random<R: Rng>(rng: &mut R) -> Self;
    fn is_zero(&self) -> bool;
    fn normalize(&mut self);
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct G1(groups::G1);

impl G1 {
    /// Four-term Straus MSM for public 128-bit scalars (variable time).
    /// The subset table is built here, not supplied or trusted by the caller.
    pub fn msm_128(terms: &[(G1, u128); 4]) -> G1 {
        let mut table = [groups::G1::zero(); 16];
        for mask in 1usize..16 {
            let bit = mask.trailing_zeros() as usize;
            table[mask] = table[mask ^ (1 << bit)] + terms[bit].0 .0;
        }
        let mut result = groups::G1::zero();
        for bit in (0..128).rev() {
            result = result.double();
            let mut mask = 0;
            for (index, (_, scalar)) in terms.iter().enumerate() {
                mask |= ((scalar >> bit) as usize & 1) << index;
            }
            result = result + table[mask];
        }
        G1(result)
    }

    pub fn new(x: Fq, y: Fq, z: Fq) -> Self {
        G1(groups::G1::new(x.0, y.0, z.0))
    }

    pub fn x(&self) -> Fq {
        Fq(self.0.x().clone())
    }

    pub fn set_x(&mut self, x: Fq) {
        *self.0.x_mut() = x.0
    }

    pub fn y(&self) -> Fq {
        Fq(self.0.y().clone())
    }

    pub fn set_y(&mut self, y: Fq) {
        *self.0.y_mut() = y.0
    }

    pub fn z(&self) -> Fq {
        Fq(self.0.z().clone())
    }

    pub fn set_z(&mut self, z: Fq) {
        *self.0.z_mut() = z.0
    }

    pub fn b() -> Fq {
        Fq(G1Params::coeff_b())
    }

    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CurveError> {
        if bytes.len() != 33 {
            return Err(CurveError::InvalidEncoding);
        }

        let sign = bytes[0];
        let fq = Fq::from_slice(&bytes[1..])?;
        let x = fq;
        let y_squared = (fq * fq * fq) + Self::b();

        let mut y = y_squared.sqrt().ok_or(CurveError::NotMember)?;

        if sign == 2 && y.into_u256().get_bit(0).expect("bit 0 always exist; qed") {
            y = y.neg();
        } else if sign == 3 && !y.into_u256().get_bit(0).expect("bit 0 always exist; qed") {
            y = y.neg();
        } else if sign != 3 && sign != 2 {
            return Err(CurveError::InvalidEncoding);
        }
        AffineG1::new(x, y)
            .map_err(|_| CurveError::NotMember)
            .map(Into::into)
    }
}

impl Group for G1 {
    fn zero() -> Self {
        G1(groups::G1::zero())
    }
    fn one() -> Self {
        G1(groups::G1::one())
    }
    fn random<R: Rng>(rng: &mut R) -> Self {
        G1(groups::G1::random(rng))
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    fn normalize(&mut self) {
        let new = match self.0.to_affine() {
            Some(a) => a,
            None => return,
        };

        self.0 = new.to_jacobian();
    }
}

impl Add<G1> for G1 {
    type Output = G1;

    fn add(self, other: G1) -> G1 {
        G1(self.0 + other.0)
    }
}

impl Sub<G1> for G1 {
    type Output = G1;

    fn sub(self, other: G1) -> G1 {
        G1(self.0 - other.0)
    }
}

impl Neg for G1 {
    type Output = G1;

    fn neg(self) -> G1 {
        G1(-self.0)
    }
}

impl Mul<Fr> for G1 {
    type Output = G1;

    fn mul(self, other: Fr) -> G1 {
        G1(self.0 * other.0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct AffineG1(groups::AffineG1);

impl AffineG1 {
    pub fn new(x: Fq, y: Fq) -> Result<Self, GroupError> {
        Ok(AffineG1(groups::AffineG1::new(x.0, y.0)?))
    }

    pub fn x(&self) -> Fq {
        Fq(self.0.x().clone())
    }

    pub fn set_x(&mut self, x: Fq) {
        *self.0.x_mut() = x.0
    }

    pub fn y(&self) -> Fq {
        Fq(self.0.y().clone())
    }

    pub fn set_y(&mut self, y: Fq) {
        *self.0.y_mut() = y.0
    }

    pub fn from_jacobian(g1: G1) -> Option<Self> {
        g1.0.to_affine().map(|x| AffineG1(x))
    }
}

impl From<AffineG1> for G1 {
    fn from(affine: AffineG1) -> Self {
        G1(affine.0.to_jacobian())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct G2(groups::G2);

impl G2 {
    pub fn new(x: Fq2, y: Fq2, z: Fq2) -> Self {
        G2(groups::G2::new(x.0, y.0, z.0))
    }

    pub fn x(&self) -> Fq2 {
        Fq2(self.0.x().clone())
    }

    pub fn set_x(&mut self, x: Fq2) {
        *self.0.x_mut() = x.0
    }

    pub fn y(&self) -> Fq2 {
        Fq2(self.0.y().clone())
    }

    pub fn set_y(&mut self, y: Fq2) {
        *self.0.y_mut() = y.0
    }

    pub fn z(&self) -> Fq2 {
        Fq2(self.0.z().clone())
    }

    pub fn set_z(&mut self, z: Fq2) {
        *self.0.z_mut() = z.0
    }

    pub fn b() -> Fq2 {
        Fq2(G2Params::coeff_b())
    }

    pub fn from_compressed(bytes: &[u8]) -> Result<Self, CurveError> {
        if bytes.len() != 65 {
            return Err(CurveError::InvalidEncoding);
        }

        let sign = bytes[0];
        let x = Fq2::from_slice(&bytes[1..])?;

        let y_squared = (x * x * x) + G2::b();
        let y = y_squared.sqrt().ok_or(CurveError::NotMember)?;
        let y_neg = -y;

        let y_gt = y.0.to_u512() > y_neg.0.to_u512();

        let e_y = if sign == 10 {
            if y_gt {
                y_neg
            } else {
                y
            }
        } else if sign == 11 {
            if y_gt {
                y
            } else {
                y_neg
            }
        } else {
            return Err(CurveError::InvalidEncoding);
        };

        AffineG2::new(x, e_y)
            .map_err(|_| CurveError::NotMember)
            .map(Into::into)
    }
}

impl Group for G2 {
    fn zero() -> Self {
        G2(groups::G2::zero())
    }
    fn one() -> Self {
        G2(groups::G2::one())
    }
    fn random<R: Rng>(rng: &mut R) -> Self {
        G2(groups::G2::random(rng))
    }
    fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    fn normalize(&mut self) {
        let new = match self.0.to_affine() {
            Some(a) => a,
            None => return,
        };

        self.0 = new.to_jacobian();
    }
}

impl Add<G2> for G2 {
    type Output = G2;

    fn add(self, other: G2) -> G2 {
        G2(self.0 + other.0)
    }
}

impl Sub<G2> for G2 {
    type Output = G2;

    fn sub(self, other: G2) -> G2 {
        G2(self.0 - other.0)
    }
}

impl Neg for G2 {
    type Output = G2;

    fn neg(self) -> G2 {
        G2(-self.0)
    }
}

impl Mul<Fr> for G2 {
    type Output = G2;

    fn mul(self, other: Fr) -> G2 {
        G2(self.0 * other.0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct Gt(fields::Fq12);

impl Gt {
    pub fn one() -> Self {
        Gt(fields::Fq12::one())
    }
    pub fn pow(&self, exp: Fr) -> Self {
        Gt(self.0.pow(exp.0))
    }
    pub fn inverse(&self) -> Option<Self> {
        self.0.inverse().map(Gt)
    }
    pub fn final_exponentiation(&self) -> Option<Self> {
        self.0.final_exponentiation().map(Gt)
    }
}

impl Mul<Gt> for Gt {
    type Output = Gt;

    fn mul(self, other: Gt) -> Gt {
        Gt(self.0 * other.0)
    }
}

pub fn pairing(p: G1, q: G2) -> Gt {
    Gt(groups::pairing(&p.0, &q.0))
}

pub fn pairing_batch(pairs: &[(G1, G2)]) -> Gt {
    let mut ps: Vec<groups::G1> = Vec::new();
    let mut qs: Vec<groups::G2> = Vec::new();
    for (p, q) in pairs {
        ps.push(p.0);
        qs.push(q.0);
    }
    Gt(groups::pairing_batch(&ps, &qs))
}

pub fn miller_loop_batch(pairs: &[(G2, G1)]) -> Result<Gt, CurveError> {
    let mut ps: Vec<groups::G2Precomp> = Vec::new();
    let mut qs: Vec<groups::AffineG<groups::G1Params>> = Vec::new();
    for (p, q) in pairs {
        ps.push(
            p.0.to_affine()
                .ok_or(CurveError::ToAffineConversion)?
                .precompute(),
        );
        qs.push(q.0.to_affine().ok_or(CurveError::ToAffineConversion)?);
    }
    Ok(Gt(groups::miller_loop_batch(&ps, &qs)))
}

/// Canonical prepared target (384 bytes), then two 87-line G2 tables.
pub const PREPARED_PAIRING_BYTES: usize = 384 + 2 * groups::G2_PRECOMP_BYTES;

/// Public fixed-key data for `e(a,b) * e(-ic,gamma) * e(-c,delta) = e(alpha,beta)`.
///
/// Preparation validates the source points. Decoding only validates the encoding:
/// the entire encoded value must be committed before accepting any proof, and its
/// producer must have validated the source key and derived these coefficients
/// before that commitment (in particular, before funding a contract).
pub struct PreparedPairing {
    target: fields::Fq12,
    gamma: groups::G2Precomp,
    delta: groups::G2Precomp,
}

impl PreparedPairing {
    /// Validate every fixed point, rejecting infinity, off-curve points, and
    /// points outside the prime-order subgroups, then derive the fixed data.
    pub fn prepare(alpha: G1, beta: G2, gamma: G2, delta: G2) -> Option<Self> {
        fn fixed_g2(point: G2) -> Option<groups::AffineG2> {
            let point = point.0.to_affine()?;
            groups::AffineG2::new(*point.x(), *point.y()).ok()
        }

        let alpha = alpha.0.to_affine()?;
        let alpha = groups::AffineG1::new(*alpha.x(), *alpha.y()).ok()?;
        let beta = fixed_g2(beta)?;
        let gamma = fixed_g2(gamma)?;
        let delta = fixed_g2(delta)?;
        Some(Self {
            target: beta
                .precompute()
                .miller_loop(&alpha)
                .final_exponentiation()?,
            gamma: gamma.precompute(),
            delta: delta.precompute(),
        })
    }

    /// Encode exactly `PREPARED_PAIRING_BYTES` public bytes.
    ///
    /// Order: target Fq12 c0,c1; each Fq6 c0,c1,c2; each Fq2 c0,c1.
    /// Then gamma's 87 coefficients and delta's 87 coefficients, each ordered
    /// ell_0,ell_vw,ell_vv. Every Fq x is encoded as x * 2^256 mod q,
    /// a canonical residue below q in exactly 32 big-endian bytes. This
    /// representation is specific to prepared data, not proof/source coordinates.
    pub fn encode(&self, output: &mut [u8]) -> Option<()> {
        if output.len() != PREPARED_PAIRING_BYTES {
            return None;
        }
        let delta_start = 384 + groups::G2_PRECOMP_BYTES;
        self.target.to_montgomery_big_endian(&mut output[..384])?;
        self.gamma.encode(&mut output[384..delta_start])?;
        self.delta.encode(&mut output[delta_start..])
    }

    /// Decode producer-validated, committed fixed data, NEVER witness data.
    ///
    /// Enforces exact length, Montgomery residues below q, and a nonzero target.
    /// This does NOT establish that the target or lines came from `prepare`,
    /// nor authenticate a source key. The trusted producer must validate and
    /// prepare that key before the entire encoding is committed.
    pub fn decode_committed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PREPARED_PAIRING_BYTES {
            return None;
        }
        let target = fields::Fq12::from_montgomery_big_endian(&bytes[..384])?;
        if target.is_zero() {
            return None;
        }
        let delta_start = 384 + groups::G2_PRECOMP_BYTES;
        Some(Self {
            target,
            gamma: groups::G2Precomp::decode_committed(&bytes[384..delta_start])?,
            delta: groups::G2Precomp::decode_committed(&bytes[delta_start..])?,
        })
    }

    /// Verify with shared Miller squares and one final exponentiation.
    ///
    /// The caller must validate the proof points a,b,c (canonical, on-curve,
    /// subgroup, non-infinity) and derive ic from its validated public inputs
    /// and key. A computed ic at infinity is valid and omits its pairing.
    /// Fixed line tables are borrowed; only b is prepared for this call.
    /// Returns None for an infinite proof point or a zero Miller product,
    /// including zero products induced by malformed committed coefficients.
    pub fn verify(&self, a: G1, b: G2, c: G1, ic: G1) -> Option<bool> {
        let a = a.0.to_affine()?;
        let b = b.0.to_affine()?.precompute();
        let c = (-c.0).to_affine()?;
        let product = match (-ic.0).to_affine() {
            Some(ic) => {
                groups::miller_loop_batch_lines(&[(&b, a), (&self.gamma, ic), (&self.delta, c)])
            }
            None => groups::miller_loop_batch_lines(&[(&b, a), (&self.delta, c)]),
        };
        Some(product.final_exponentiation()? == self.target)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub struct AffineG2(groups::AffineG2);

impl AffineG2 {
    pub fn new(x: Fq2, y: Fq2) -> Result<Self, GroupError> {
        Ok(AffineG2(groups::AffineG2::new(x.0, y.0)?))
    }

    pub fn x(&self) -> Fq2 {
        Fq2(self.0.x().clone())
    }

    pub fn set_x(&mut self, x: Fq2) {
        *self.0.x_mut() = x.0
    }

    pub fn y(&self) -> Fq2 {
        Fq2(self.0.y().clone())
    }

    pub fn set_y(&mut self, y: Fq2) {
        *self.0.y_mut() = y.0
    }

    pub fn from_jacobian(g2: G2) -> Option<Self> {
        g2.0.to_affine().map(|x| AffineG2(x))
    }
}

impl From<AffineG2> for G2 {
    fn from(affine: AffineG2) -> Self {
        G2(affine.0.to_jacobian())
    }
}

#[cfg(test)]
mod tests {
    use super::{Fq, Fq2, G1, G2};
    use alloc::vec::Vec;

    fn hex(s: &'static str) -> Vec<u8> {
        use rustc_hex::FromHex;
        s.from_hex().unwrap()
    }

    #[test]
    fn g1_from_compressed() {
        let g1 = G1::from_compressed(&hex(
            "0230644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
        ))
        .expect("Invalid g1 decompress result");
        assert_eq!(
            g1.x(),
            Fq::from_str(
                "21888242871839275222246405745257275088696311157297823662689037894645226208582"
            )
            .unwrap()
        );
        assert_eq!(
            g1.y(),
            Fq::from_str(
                "3969792565221544645472939191694882283483352126195956956354061729942568608776"
            )
            .unwrap()
        );
        assert_eq!(g1.z(), Fq::one());
    }

    #[test]
    fn g2_from_compressed() {
        let g2 = G2::from_compressed(
            &hex("0a023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a")
        ).expect("Valid g2 point hex encoding");

        assert_eq!(
            g2.x(),
            Fq2::new(
                Fq::from_str(
                    "5923585509243758863255447226263146374209884951848029582715967108651637186684"
                )
                .unwrap(),
                Fq::from_str(
                    "5336385337059958111259504403491065820971993066694750945459110579338490853570"
                )
                .unwrap(),
            )
        );

        assert_eq!(
            g2.y(),
            Fq2::new(
                Fq::from_str(
                    "10374495865873200088116930399159835104695426846400310764827677226300185211748"
                )
                .unwrap(),
                Fq::from_str(
                    "5256529835065685814318509161957442385362539991735248614869838648137856366932"
                )
                .unwrap(),
            )
        );

        // 0b prefix is point reflection on the curve
        let g2 = -G2::from_compressed(
            &hex("0b023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a")
        ).expect("Valid g2 point hex encoding");

        assert_eq!(
            g2.x(),
            Fq2::new(
                Fq::from_str(
                    "5923585509243758863255447226263146374209884951848029582715967108651637186684"
                )
                .unwrap(),
                Fq::from_str(
                    "5336385337059958111259504403491065820971993066694750945459110579338490853570"
                )
                .unwrap(),
            )
        );

        assert_eq!(
            g2.y(),
            Fq2::new(
                Fq::from_str(
                    "10374495865873200088116930399159835104695426846400310764827677226300185211748"
                )
                .unwrap(),
                Fq::from_str(
                    "5256529835065685814318509161957442385362539991735248614869838648137856366932"
                )
                .unwrap(),
            )
        );

        // valid point but invalid sign prefix
        assert!(
            G2::from_compressed(
                &hex("0c023aed31b5a9e486366ea9988b05dba469c6206e58361d9c065bbea7d928204a761efc6e4fa08ed227650134b52c7f7dd0463963e8a4bf21f4899fe5da7f984a")
            ).is_err()
        );
    }
}
