use crate::hacspec_helper::*;


#[nat_mod("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 64)]
pub struct P256FieldElement {}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct P256Point(pub P256FieldElement, pub P256FieldElement, pub bool);

impl P256FieldElement {
    pub fn inv0(self) -> Self {
        if self == Self::zero() {
            Self::zero()
        } else {
            self.inv()
        }
    }

    pub fn sgn0(self) -> bool {
        self.bit(0)
    }

    pub fn is_square(&self) -> bool {
        use num_bigint::BigUint;
        let p = BigUint::from_bytes_be(&Self::MODULUS);
        let exp = (&p - BigUint::from(1u8)) / BigUint::from(2u8);
        let base = BigUint::from_bytes_be(&self.value());

        let res = Self::from_bigint(base.modpow(&exp, &p));
        res == Self::zero() || res == Self::from_u128(1u128)
    }

    pub fn sqrt(&self) -> Self {
        // p = 3 (mod 4)
        use num_bigint::BigUint;
        let p = BigUint::from_bytes_be(&Self::MODULUS);
        let c1 = (&p + BigUint::from(1u8)) / BigUint::from(4u8);
        let base = BigUint::from_bytes_be(&self.value());

        Self::from_bigint(base.modpow(&c1, &p))
    }

    pub fn neg(self) -> Self {
        Self::zero() - self
    }
}

pub fn clear_cofactor(p: P256Point) -> P256Point {
    // no-op for P-256
    p
}

pub fn gadd(p: P256Point, q: P256Point) -> P256Point {
    if p.2 {
        // p at infinity
        q
    } else {
        if q.2 {
            // q at infinity
            p
        } else {
            if p == q {
                gdouble(p)
            } else {
                gadd_noninf(p, q)
            }
        }
    }
}

fn gadd_noninf(p: P256Point, q: P256Point) -> P256Point {
    let P256Point(px, py, p_inf) = p;
    let P256Point(qx, qy, q_inf) = q;
    assert!(!(p_inf || q_inf));

    if px == qx && py == qy.neg() {
        P256Point(P256FieldElement::zero(), P256FieldElement::zero(), true)
    } else {
        let d = (qy - py) * (qx - px).inv();
        let out_x = d.pow(2) - px - qx;
        let out_y = d * (px - out_x) - py;

        P256Point(out_x, out_y, false)
    }
}

fn gdouble(p: P256Point) -> P256Point {
    let P256Point(px, py, p_inf) = p;
    assert!(!p_inf);
    if py == P256FieldElement::zero() {
        P256Point(P256FieldElement::zero(), P256FieldElement::zero(), true)
    } else {
        let a = P256FieldElement::from_u128(3u128).neg();
        let d = (P256FieldElement::from_u128(3) * px.pow(2) + a)
            * (P256FieldElement::from_u128(2) * py).inv();
        let out_x = d.pow(2) - P256FieldElement::from_u128(2) * px;
        let out_y = d * (px - out_x) - py;

        P256Point(out_x, out_y, false)
    }
}

#[test]
fn neg() {
    let x = P256FieldElement::from_hex("02");
    let x_neg = x.neg();
    let z = x + x_neg;
    assert_eq!(P256FieldElement::ZERO.as_ref(), z.as_ref());
}

#[test]
fn add() {
    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex("01");
    let z = x + y;
    assert_eq!(P256FieldElement::ZERO.as_ref(), z.as_ref());

    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex("02");
    let z = x + y;
    assert_eq!(P256FieldElement::from_hex("01").as_ref(), z.as_ref());
}

#[test]
fn mul() {
    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex("01");
    let z = x * y;
    assert_eq!(x.as_ref(), z.as_ref());

    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex("02");
    let z = x * y;
    assert_eq!(
        P256FieldElement::from_hex(
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd"
        )
        .as_ref(),
        z.as_ref()
    );
}

#[test]
fn sub() {
    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex("01");
    let z = x - y;
    assert_eq!(
        P256FieldElement::from_hex(
            "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd"
        )
        .as_ref(),
        z.as_ref()
    );

    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let y = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffd",
    );
    let z = x - y;
    assert_eq!(P256FieldElement::from_hex("01").as_ref(), z.as_ref());
}

#[test]
fn inv() {
    let x = P256FieldElement::from_hex(
        "ffffffff00000001000000000000000000000000fffffffffffffffffffffffe",
    );
    let x_inv = x.inv();
    let z = x * x_inv;
    assert_eq!(P256FieldElement::from_hex("01").as_ref(), z.as_ref());
}
