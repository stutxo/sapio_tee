mod fp;
mod fq12;
mod fq2;
mod fq6;

use crate::arith::U256;
use alloc::fmt::Debug;
use core::ops::{Add, Mul, Neg, Sub};
use rand::Rng;

pub use self::fp::{const_fq, Fq, Fr};
pub use self::fq12::Fq12;
pub use self::fq2::Fq2;
pub use self::fq6::Fq6;

pub trait FieldElement:
    Sized
    + Copy
    + Clone
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + PartialEq
    + Eq
    + Debug
{
    fn zero() -> Self;
    fn one() -> Self;
    fn random<R: Rng>(_: &mut R) -> Self;
    fn is_zero(&self) -> bool;
    fn squared(&self) -> Self {
        (*self) * (*self)
    }
    fn inverse(self) -> Option<Self>;
    fn pow<I: Into<U256>>(&self, by: I) -> Self {
        let mut res = Self::one();

        for i in by.into().bits() {
            res = res.squared();
            if i {
                res = *self * res;
            }
        }

        res
    }
}

#[cfg(test)]
mod tests;

#[test]
fn test_fr() {
    tests::field_trials::<Fr>();
}

#[test]
fn test_fq() {
    tests::field_trials::<Fq>();
}

#[test]
fn test_fq2() {
    tests::field_trials::<Fq2>();
}

#[test]
fn test_str() {
    assert_eq!(
        -Fr::one(),
        Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616"
        )
        .unwrap()
    );
    assert_eq!(
        -Fq::one(),
        Fq::from_str(
            "21888242871839275222246405745257275088696311157297823662689037894645226208582"
        )
        .unwrap()
    );
}

#[test]
fn test_fq6() {
    tests::field_trials::<Fq6>();
}

#[test]
fn test_fq12() {
    tests::field_trials::<Fq12>();
}

#[test]
fn fq12_test_vector() {
    let start = Fq12::new(
        Fq6::new(
            Fq2::new(
                Fq::from_str(
                    "19797905000333868150253315089095386158892526856493194078073564469188852136946",
                )
                .unwrap(),
                Fq::from_str(
                    "10509658143212501778222314067134547632307419253211327938344904628569123178733",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "208316612133170645758860571704540129781090973693601051684061348604461399206",
                )
                .unwrap(),
                Fq::from_str(
                    "12617661120538088237397060591907161689901553895660355849494983891299803248390",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "2897490589776053688661991433341220818937967872052418196321943489809183508515",
                )
                .unwrap(),
                Fq::from_str(
                    "2730506433347642574983433139433778984782882168213690554721050571242082865799",
                )
                .unwrap(),
            ),
        ),
        Fq6::new(
            Fq2::new(
                Fq::from_str(
                    "17870056122431653936196746815433147921488990391314067765563891966783088591110",
                )
                .unwrap(),
                Fq::from_str(
                    "14314041658607615069703576372547568077123863812415914883625850585470406221594",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "10123533891707846623287020000407963680629966110211808794181173248765209982878",
                )
                .unwrap(),
                Fq::from_str(
                    "5062091880848845693514855272640141851746424235009114332841857306926659567101",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "9839781502639936537333620974973645053542086898304697594692219798017709586567",
                )
                .unwrap(),
                Fq::from_str(
                    "1583892292110602864638265389721494775152090720173641072176370350017825640703",
                )
                .unwrap(),
            ),
        ),
    );

    // Do a bunch of arbitrary stuff to the element

    let mut next = start.clone();
    for _ in 0..100 {
        next = next * start;
    }

    let cpy = next.clone();

    for _ in 0..10 {
        next = next.squared();
    }

    for _ in 0..10 {
        next = next + start;
        next = next - cpy;
        next = -next;
    }

    next = next.squared();

    let finally = Fq12::new(
        Fq6::new(
            Fq2::new(
                Fq::from_str(
                    "18388750939593263065521177085001223024106699964957029146547831509155008229833",
                )
                .unwrap(),
                Fq::from_str(
                    "18370529854582635460997127698388761779167953912610241447912705473964014492243",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "3691824277096717481466579496401243638295254271265821828017111951446539785268",
                )
                .unwrap(),
                Fq::from_str(
                    "20513494218085713799072115076991457239411567892860153903443302793553884247235",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "12214155472433286415803224222551966441740960297013786627326456052558698216399",
                )
                .unwrap(),
                Fq::from_str(
                    "10987494248070743195602580056085773610850106455323751205990078881956262496575",
                )
                .unwrap(),
            ),
        ),
        Fq6::new(
            Fq2::new(
                Fq::from_str(
                    "5134522153456102954632718911439874984161223687865160221119284322136466794876",
                )
                .unwrap(),
                Fq::from_str(
                    "20119236909927036376726859192821071338930785378711977469360149362002019539920",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "8839766648621210419302228913265679710586991805716981851373026244791934012854",
                )
                .unwrap(),
                Fq::from_str(
                    "9103032146464138788288547957401673544458789595252696070370942789051858719203",
                )
                .unwrap(),
            ),
            Fq2::new(
                Fq::from_str(
                    "10378379548636866240502412547812481928323945124508039853766409196375806029865",
                )
                .unwrap(),
                Fq::from_str(
                    "9021627154807648093720460686924074684389554332435186899318369174351765754041",
                )
                .unwrap(),
            ),
        ),
    );

    assert_eq!(finally, next);
}

#[test]
fn cyclotomic_seed_chain_matches_ordinary_powering() {
    // Signed exponents require cyclotomic inputs. Project deterministic public
    // field samples with the easy exponent, and include the identity boundary.
    // The reference uses ordinary squaring and inversion, not cyclotomic formulas.
    for index in 0..16u64 {
        let coordinate = |offset| {
            let value = index * 12 + offset;
            Fq2::new(
                Fq::new(U256::from(value)).unwrap(),
                Fq::new(U256::from(value * value + 1)).unwrap(),
            )
        };
        let sample = Fq12::new(
            Fq6::new(coordinate(1), coordinate(3), coordinate(5)),
            Fq6::new(coordinate(7), coordinate(9), coordinate(11)),
        );
        let easy = sample.unitary_inverse() * sample.inverse().unwrap();
        let cyclotomic = if index == 0 {
            Fq12::one()
        } else {
            easy.frobenius_map(2) * easy
        };
        assert_eq!(cyclotomic * cyclotomic.unitary_inverse(), Fq12::one());
        assert_eq!(cyclotomic.cyclotomic_squared(), cyclotomic.squared());
        let expected = cyclotomic
            .pow(U256::from(4965661367192848881u64))
            .inverse()
            .unwrap();
        assert_eq!(cyclotomic.exp_by_neg_z(), expected);
    }
}
