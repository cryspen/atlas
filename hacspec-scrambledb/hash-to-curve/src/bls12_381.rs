// BLS: y^2 = x^3 + 4
#![allow(unused)]

use crate::hacspec_helper::*;
use crate::prime_curve::FieldArithmetic;
use natmod::nat_mod;
use p256::NatMod;

#[nat_mod("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 48)]
pub struct BLS12FieldElement {}

#[nat_mod("8000000000000000000000000000000000000000000000000000000000000000", 32)]
pub struct Scalar {}

//bool is "isPointAtInfinity"
#[allow(non_camel_case_types)]
pub type BLS12_G1 = (BLS12FieldElement, BLS12FieldElement, bool);
pub type Fp2 = (BLS12FieldElement, BLS12FieldElement); //(10, 8) = (10+8u) : u² = -1
#[allow(non_camel_case_types)]
pub type BLS12_G2 = (Fp2, Fp2, bool);
pub type Fp6 = (Fp2, Fp2, Fp2); //v³ = u + 1
pub type Fp12 = (Fp6, Fp6); //w² = v

/* Arithmetic for FP2 elements */
pub fn fp2fromfp(n: BLS12FieldElement) -> Fp2 {
    (n, BLS12FieldElement::zero())
}

pub fn fp2zero() -> Fp2 {
    fp2fromfp(BLS12FieldElement::zero())
}

pub fn fp2neg(n: Fp2) -> Fp2 {
    let (n1, n2) = n;
    (
        BLS12FieldElement::zero() - n1,
        BLS12FieldElement::zero() - n2,
    )
}

pub fn fp2add(n: Fp2, m: Fp2) -> Fp2 {
    //Coordinate wise
    let (n1, n2) = n;
    let (m1, m2) = m;
    (n1 + m1, n2 + m2)
}

pub fn fp2sub(n: Fp2, m: Fp2) -> Fp2 {
    fp2add(n, fp2neg(m))
}

pub fn fp2mul(n: Fp2, m: Fp2) -> Fp2 {
    //(a+bu)*(c+du) = ac + adu + bcu + bdu^2 = ac - bd + (ad + bc)u
    let (n1, n2) = n;
    let (m1, m2) = m;
    let x1 = (n1 * m1) - (n2 * m2);
    let x2 = (n1 * m2) + (n2 * m1);
    (x1, x2)
}

pub fn fp2inv(n: Fp2) -> Fp2 {
    let (n1, n2) = n;
    let t0 = n1 * n1 + (n2 * n2);
    let t1 = t0.inv();
    let x1 = n1 * t1;
    let x2 = BLS12FieldElement::zero() - (n2 * t1);
    (x1, x2)
}

pub fn fp2conjugate(n: Fp2) -> Fp2 {
    let (n1, n2) = n;
    (n1, BLS12FieldElement::zero() - n2)
}

// impl<T: std::ops::Mul<T>> std::ops::Mul<(T, T)> for (T, T) {
//     type Output = Fp2;

//     fn mul(self, rhs: Fp2) -> Self::Output {
//         todo!()
//     }
// }

// impl std::ops::Add<Fp2> for Fp2 {
//     type Output = Fp2;

//     fn add(self, rhs: Fp2) -> Self::Output {
//         todo!()
//     }
// }

// impl std::ops::Neg for Fp2 {
//     type Output = Fp2;

//     fn neg(self) -> Self::Output {
//         fp2neg(self)
//     }
// }

impl FieldArithmetic for Fp2 {
    fn is_square(&self) -> bool {
        todo!()
    }
    fn sqrt(self) -> Self {
        todo!()
    }
    fn sgn0(self) -> bool {
        todo!()
    }
    fn inv(self) -> Self {
        todo!()
    }
    fn inv0(self) -> Self {
        todo!()
    }
    fn pow(self, rhs: u128) -> Self {
        todo!()
    }
    fn zero() -> Self {
        todo!()
    }
    fn one() -> Self {
        todo!()
    }
    fn from_u128(x: u128) -> Self {
        todo!()
    }
}

/* Arithmetic for Fp6 elements */
//Algorithms from: https://eprint.iacr.org/2010/354.pdf
fn fp6fromfp2(n: Fp2) -> Fp6 {
    (n, fp2zero(), fp2zero())
}

fn fp6zero() -> Fp6 {
    fp6fromfp2(fp2zero())
}

fn fp6neg(n: Fp6) -> Fp6 {
    let (n1, n2, n3) = n;
    (
        fp2sub(fp2zero(), n1),
        fp2sub(fp2zero(), n2),
        fp2sub(fp2zero(), n3),
    )
}

fn fp6add(n: Fp6, m: Fp6) -> Fp6 {
    let (n1, n2, n3) = n;
    let (m1, m2, m3) = m;
    (fp2add(n1, m1), fp2add(n2, m2), fp2add(n3, m3))
}

fn fp6sub(n: Fp6, m: Fp6) -> Fp6 {
    fp6add(n, fp6neg(m))
}

fn fp6mul(n: Fp6, m: Fp6) -> Fp6 {
    let (n1, n2, n3) = n;
    let (m1, m2, m3) = m;
    let eps = (BLS12FieldElement::one(), BLS12FieldElement::one()); //1 + u
    let t1 = fp2mul(n1, m1);
    let t2 = fp2mul(n2, m2);
    let t3 = fp2mul(n3, m3);
    let t4 = fp2mul(fp2add(n2, n3), fp2add(m2, m3)); // (n2 + n3) * (m2 + m3)
    let t5 = fp2sub(fp2sub(t4, t2), t3); //t4 - t2 - t3
    let x = fp2add(fp2mul(t5, eps), t1); // t5 * eps + t1

    let t4 = fp2mul(fp2add(n1, n2), fp2add(m1, m2)); //(n1 + n2) * (m1 + m2)
    let t5 = fp2sub(fp2sub(t4, t1), t2); //t4 - t1 - t2
    let y = fp2add(t5, fp2mul(eps, t3)); //t5 + (eps * t3)

    let t4 = fp2mul(fp2add(n1, n3), fp2add(m1, m3)); //(n1 + n3) * (m1 + m3)
    let t5 = fp2sub(fp2sub(t4, t1), t3); //t4 - t1 - t3
    let z = fp2add(t5, t2); //t5 + t2
    (x, y, z)
}

fn fp6inv(n: Fp6) -> Fp6 {
    let (n1, n2, n3) = n;
    let eps = (BLS12FieldElement::one(), BLS12FieldElement::one()); //1 + u
    let t1 = fp2mul(n1, n1); //n1^2
    let t2 = fp2mul(n2, n2); //n2^2
    let t3 = fp2mul(n3, n3); //n3^2
    let t4 = fp2mul(n1, n2); //n1 * n2
    let t5 = fp2mul(n1, n3); //n1 * n3
    let t6 = fp2mul(n2, n3); //n2 * n3
    let x0 = fp2sub(t1, fp2mul(eps, t6)); //t1 - (eps * t6)
    let y0 = fp2sub(fp2mul(eps, t3), t4); //(eps * t3) - t4
    let z0 = fp2sub(t2, t5); //t2 - t5
    let t0 = fp2mul(n1, x0); //n1 * x0
    let t0 = fp2add(t0, fp2mul(eps, fp2mul(n3, y0))); //t0 + (eps * n3 * y0)
    let t0 = fp2add(t0, fp2mul(eps, fp2mul(n2, z0))); //t0 + (eps * n2 * z0)
    let t0 = fp2inv(t0); //t0^-1
    let x = fp2mul(x0, t0); //x0 * t0
    let y = fp2mul(y0, t0); // y0 * t0
    let z = fp2mul(z0, t0); // z0 * t0
    (x, y, z)
}

/* Arithmetic for Fp12 elements */
// Algorithms from: https://eprint.iacr.org/2010/354.pdf
pub fn fp12fromfp6(n: Fp6) -> Fp12 {
    (n, fp6zero())
}

pub fn fp12neg(n: Fp12) -> Fp12 {
    let (n1, n2) = n;
    (fp6sub(fp6zero(), n1), fp6sub(fp6zero(), n2))
}

pub fn fp12add(n: Fp12, m: Fp12) -> Fp12 {
    let (n1, n2) = n;
    let (m1, m2) = m;
    (fp6add(n1, m1), fp6add(n2, m2))
}

pub fn fp12sub(n: Fp12, m: Fp12) -> Fp12 {
    fp12add(n, fp12neg(m))
}

pub fn fp12mul(n: Fp12, m: Fp12) -> Fp12 {
    let (n1, n2) = n;
    let (m1, m2) = m;
    let gamma = (fp2zero(), fp2fromfp(BLS12FieldElement::one()), fp2zero()); //0 + v + 0 (c0, c1v, c2v^2)

    let t1 = fp6mul(n1, m1); //n1 * n2
    let t2 = fp6mul(n2, m2); //n2 * m2
    let x = fp6add(t1, fp6mul(t2, gamma)); //t1 + (t2 * gamma)
    let y = fp6mul(fp6add(n1, n2), fp6add(m1, m2)); //(n1 + n2) * (m1 + m2)
    let y = fp6sub(fp6sub(y, t1), t2); //y - t1 - t2
    (x, y)
}

pub fn fp12inv(n: Fp12) -> Fp12 {
    let (n1, n2) = n;
    let gamma = (fp2zero(), fp2fromfp(BLS12FieldElement::one()), fp2zero()); //0 + v + 0 (c0, c1v, c2v^2)

    let t1 = fp6mul(n1, n1); //n1^2
    let t2 = fp6mul(n2, n2); //n2^2
    let t1 = fp6sub(t1, fp6mul(gamma, t2)); //t1 - (gamma * t2)
    let t2 = fp6inv(t1); //t1^-1
    let x = fp6mul(n1, t2); //n1 * t2
    let y = fp6neg(fp6mul(n2, t2)); //-(n2 * t2)
    (x, y)
}

pub fn fp12exp(n: Fp12, k: Scalar) -> Fp12 {
    let mut c = fp12fromfp6(fp6fromfp2(fp2fromfp(BLS12FieldElement::one())));
    for i in 0..256 {
        //starting from second most significant bit
        c = fp12mul(c, c);
        if k.bit(255 - i) {
            c = fp12mul(c, n);
        }
    }
    c
}

pub fn fp12conjugate(n: Fp12) -> Fp12 {
    let (n1, n2) = n;
    (n1, fp6neg(n2))
}

pub fn fp12zero() -> Fp12 {
    fp12fromfp6(fp6zero())
}

/* Arithmetic in G1 */

//g1 add with no Point at Infinity
fn g1add_a(p: BLS12_G1, q: BLS12_G1) -> BLS12_G1 {
    let (x1, y1, _) = p;
    let (x2, y2, _) = q;

    let x_diff = x2 - x1;
    let y_diff = y2 - y1;
    let xovery = y_diff * x_diff.inv(); //  x / y = x * y^-1
    let x3 = xovery.pow(2) - x1 - x2;
    let y3 = xovery * (x1 - x3) - y1;
    (x3, y3, false)
}

//g1 double with no Point at Infinity
fn g1double_a(p: BLS12_G1) -> BLS12_G1 {
    let (x1, y1, _) = p;

    let x12 = x1.pow(2);
    let xovery = (BLS12FieldElement::from_u128(3) * x12) * (BLS12FieldElement::two() * y1).inv();
    let x3 = xovery.pow(2) - BLS12FieldElement::two() * x1;
    let y3 = xovery * (x1 - x3) - y1;
    (x3, y3, false)
}
/* Wrapper functions with Point of Infinity */
pub fn g1double(p: BLS12_G1) -> BLS12_G1 {
    let (_x1, y1, inf1) = p;
    if y1 != BLS12FieldElement::zero() && !inf1 {
        g1double_a(p)
    } else {
        (BLS12FieldElement::zero(), BLS12FieldElement::zero(), true)
    }
}

pub fn g1add(p: BLS12_G1, q: BLS12_G1) -> BLS12_G1 {
    let (x1, y1, inf1) = p;
    let (x2, y2, inf2) = q;

    if inf1 {
        q
    } else {
        if inf2 {
            p
        } else {
            if p == q {
                g1double(p)
            } else {
                if !(x1 == x2 && y1 == BLS12FieldElement::zero() - y2) {
                    g1add_a(p, q)
                } else {
                    (BLS12FieldElement::zero(), BLS12FieldElement::zero(), true)
                }
            }
        }
    }
}

pub fn g1mul(m: Scalar, p: BLS12_G1) -> BLS12_G1 {
    let mut t = (BLS12FieldElement::zero(), BLS12FieldElement::zero(), true);
    for i in 0..256 {
        //starting from second most significant bit
        t = g1double(t);
        if m.bit(255 - i) {
            t = g1add(t, p);
        }
    }
    t
}

pub fn g1neg(p: BLS12_G1) -> BLS12_G1 {
    let (x, y, inf) = p;
    (x, BLS12FieldElement::zero() - y, inf)
}

/* Arithmetic in G2 */
//g2 add without dealing with Point at Infinity
fn g2add_a(p: BLS12_G2, q: BLS12_G2) -> BLS12_G2 {
    let (x1, y1, _) = p;
    let (x2, y2, _) = q;

    let x_diff = fp2sub(x2, x1);
    let y_diff = fp2sub(y2, y1);
    let xovery = fp2mul(y_diff, fp2inv(x_diff)); //  x / y = x * y^-1
    let t1 = fp2mul(xovery, xovery);
    let t2 = fp2sub(t1, x1);
    let x3 = fp2sub(t2, x2);
    let t1 = fp2sub(x1, x3);
    let t2 = fp2mul(xovery, t1);
    let y3 = fp2sub(t2, y1);
    (x3, y3, false)
}
//g2 double without dealing with Point at Infinity
fn g2double_a(p: BLS12_G2) -> BLS12_G2 {
    let (x1, y1, _) = p;

    let x12 = fp2mul(x1, x1);
    let t1 = fp2mul(fp2fromfp(BLS12FieldElement::from_u128(3)), x12);
    let t2 = fp2inv(fp2mul(fp2fromfp(BLS12FieldElement::two()), y1));
    let xovery = fp2mul(t1, t2);
    let t1 = fp2mul(xovery, xovery);
    let t2 = fp2mul(fp2fromfp(BLS12FieldElement::two()), x1);
    let x3 = fp2sub(t1, t2);
    let t1 = fp2sub(x1, x3);
    let t2 = fp2mul(xovery, t1);
    let y3 = fp2sub(t2, y1);
    (x3, y3, false)
}

/* Wrapper functions with Point at Infinity */
pub fn g2double(p: BLS12_G2) -> BLS12_G2 {
    let (_x1, y1, inf1) = p;
    if y1 != fp2zero() && !inf1 {
        g2double_a(p)
    } else {
        (fp2zero(), fp2zero(), true)
    }
}

pub fn g2add(p: BLS12_G2, q: BLS12_G2) -> BLS12_G2 {
    let (x1, y1, inf1) = p;
    let (x2, y2, inf2) = q;

    if inf1 {
        q
    } else {
        if inf2 {
            p
        } else {
            if p == q {
                g2double(p)
            } else {
                if !(x1 == x2 && y1 == fp2neg(y2)) {
                    g2add_a(p, q)
                } else {
                    (fp2zero(), fp2zero(), true)
                }
            }
        }
    }
}

pub fn g2mul(m: Scalar, p: BLS12_G2) -> BLS12_G2 {
    let mut t = (fp2zero(), fp2zero(), true);
    for i in 0..256 {
        //starting from second most significant bit
        t = g2double(t);
        if m.bit(255 - i) {
            t = g2add(t, p);
        }
    }
    t
}

pub fn g2neg(p: BLS12_G2) -> BLS12_G2 {
    let (x, y, inf) = p;
    (x, fp2neg(y), inf)
}

//Curve twist, allowing us to work over Fp and Fp2, instead of Fp12
fn twist(p: BLS12_G1) -> (Fp12, Fp12) {
    let (p0, p1, _) = p;
    let x = ((fp2zero(), fp2fromfp(p0), fp2zero()), fp6zero());
    let y = (fp6zero(), (fp2zero(), fp2fromfp(p1), fp2zero()));
    (x, y)
}

//Line double used in ate-pairing
fn line_double_p(r: BLS12_G2, p: BLS12_G1) -> Fp12 {
    let (r0, r1, _) = r;
    let a = fp2mul(fp2fromfp(BLS12FieldElement::from_u128(3)), fp2mul(r0, r0));
    let a = fp2mul(a, fp2inv(fp2mul(fp2fromfp(BLS12FieldElement::two()), r1)));
    let b = fp2sub(r1, fp2mul(a, r0));
    let a = fp12fromfp6(fp6fromfp2(a));
    let b = fp12fromfp6(fp6fromfp2(b));
    let (x, y) = twist(p);
    fp12neg(fp12sub(fp12sub(y, fp12mul(a, x)), b)) //y - ax - b
}

//Line addition, used in ate-pairing
fn line_add_p(r: BLS12_G2, q: BLS12_G2, p: BLS12_G1) -> Fp12 {
    let (r0, r1, _) = r;
    let (q0, q1, _) = q;
    let a = fp2mul(fp2sub(q1, r1), fp2inv(fp2sub(q0, r0)));
    let b = fp2sub(r1, fp2mul(a, r0));
    let a = fp12fromfp6(fp6fromfp2(a));
    let b = fp12fromfp6(fp6fromfp2(b));
    let (x, y) = twist(p);
    fp12neg(fp12sub(fp12sub(y, fp12mul(a, x)), b)) //y - ax - b
}

//From https://eprint.iacr.org/2010/354.pdf
fn frobenius(f: Fp12) -> Fp12 {
    let ((g0, g1, g2), (h0, h1, h2)) = f;
    let t1 = fp2conjugate(g0);
    let t2 = fp2conjugate(h0);
    let t3 = fp2conjugate(g1);
    let t4 = fp2conjugate(h1);
    let t5 = fp2conjugate(g2);
    let t6 = fp2conjugate(h2);

    /* Funky way of storing gamma11 */

    //1904D3BF02BB0667 C231BEB4202C0D1F 0FD603FD3CBD5F4F 7B2443D784BAB9C4 F67EA53D63E7813D 8D0775ED92235FB8
    let c1 = [
        0x8D0775ED92235FB8u64,
        0xF67EA53D63E7813Du64,
        0x7B2443D784BAB9C4u64,
        0x0FD603FD3CBD5F4Fu64,
        0xC231BEB4202C0D1Fu64,
        0x1904D3BF02BB0667u64,
    ];
    let c1 = c1.to_le_bytes();
    let c1 = BLS12FieldElement::from_le_bytes(&c1);

    //00FC3E2B36C4E032 88E9E902231F9FB8 54A14787B6C7B36F EC0C8EC971F63C5F 282D5AC14D6C7EC2 2CF78A126DDC4AF3
    let c2 = [
        0x2CF78A126DDC4AF3u64,
        0x282D5AC14D6C7EC2u64,
        0xEC0C8EC971F63C5Fu64,
        0x54A14787B6C7B36Fu64,
        0x88E9E902231F9FB8u64,
        0x00FC3E2B36C4E032u64,
    ];
    let c2 = c2.to_le_bytes();
    let c2 = BLS12FieldElement::from_le_bytes(&c2);

    // gamma11 = (1+u)^((p-1) / 6)
    let gamma11 = (c1, c2);
    let gamma12 = fp2mul(gamma11, gamma11);
    let gamma13 = fp2mul(gamma12, gamma11);
    let gamma14 = fp2mul(gamma13, gamma11);
    let gamma15 = fp2mul(gamma14, gamma11);

    let t2 = fp2mul(t2, gamma11);
    let t3 = fp2mul(t3, gamma12);
    let t4 = fp2mul(t4, gamma13);
    let t5 = fp2mul(t5, gamma14);
    let t6 = fp2mul(t6, gamma15);

    ((t1, t3, t5), (t2, t4, t6))
}

fn final_exponentiation(f: Fp12) -> Fp12 {
    let fp6 = fp12conjugate(f); // f^p⁶
    let finv = fp12inv(f); //f^-1
    let fp6_1 = fp12mul(fp6, finv); //f^(p⁶-1)
    let fp8 = frobenius(frobenius(fp6_1)); //f^((p⁶-1)p²)
    let f = fp12mul(fp8, fp6_1); // f = f^((p⁶-1)(p²+1))

    let u = Scalar::from_u128(0xd201000000010000); //-u
    let u_half = Scalar::from_u128(0x6900800000008000); //u/2

    //Algorithm 2 from https://eprint.iacr.org/2016/130.pdf
    //Conjugations whenever u is used, since u is actually negative - and conjugation is enough (no inversion needed)
    let t0 = fp12mul(f, f); //f²
    let t1 = fp12exp(t0, u);
    let t1 = fp12conjugate(t1); //t0^u
    let t2 = fp12exp(t1, u_half);
    let t2 = fp12conjugate(t2); //t1^(u/2)
    let t3 = fp12conjugate(f); //f^-1
    let t1 = fp12mul(t3, t1); //t3t1

    let t1 = fp12conjugate(t1); //t1^-1
    let t1 = fp12mul(t1, t2); //t1t2

    let t2 = fp12exp(t1, u);
    let t2 = fp12conjugate(t2); //t1^u

    let t3 = fp12exp(t2, u);
    let t3 = fp12conjugate(t3); //t2^u
    let t1 = fp12conjugate(t1); //t1^-1
    let t3 = fp12mul(t1, t3); //t1t3

    let t1 = fp12conjugate(t1); //t1^-1
    let t1 = frobenius(frobenius(frobenius(t1))); //t1^p³
    let t2 = frobenius(frobenius(t2)); //t2^p²
    let t1 = fp12mul(t1, t2); //t1t2

    let t2 = fp12exp(t3, u);
    let t2 = fp12conjugate(t2); //t3^u
    let t2 = fp12mul(t2, t0); //t2t0
    let t2 = fp12mul(t2, f); //t2f

    let t1 = fp12mul(t1, t2); //t1t2
    let t2 = frobenius(t3); //t3^p
    let t1 = fp12mul(t1, t2); //t1t2
    t1
}
//ate-pairing used for BLS
pub fn pairing(p: BLS12_G1, q: BLS12_G2) -> Fp12 {
    let t = Scalar::from_u128(0xd201000000010000);
    let mut r = q;
    let mut f = fp12fromfp6(fp6fromfp2(fp2fromfp(BLS12FieldElement::one())));
    for i in 1..64 {
        let lrr = line_double_p(r, p);
        r = g2double(r);
        f = fp12mul(fp12mul(f, f), lrr);
        if t.bit(64 - i - 1) {
            let lrq = line_add_p(r, q, p);
            r = g2add(r, q);
            f = fp12mul(f, lrq);
        }
    }
    final_exponentiation(fp12conjugate(f)) //conjugation since t is actually negative
}
