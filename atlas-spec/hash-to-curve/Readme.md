# Hash to Curve

| E            | Suites                            | Implemented?                        |
| ------------ | --------------------------------- | ----------------------------------- |
| NIST P-256   | P256*XMD:SHA-256_SSWU_RO*         | ✅                                  |
|              | P256*XMD:SHA-256_SSWU_NU*         | ✅                                  |
| NIST P-384   | P384*XMD:SHA-384_SSWU_RO*         | ❌ (missing curve specs)            |
|              | P384*XMD:SHA-384_SSWU_NU*         | ❌ (+ missing non-uniform encoding) |
| NIST P-521   | P521*XMD:SHA-512_SSWU_RO*         | ❌ (missing curve specs)            |
|              | P521*XMD:SHA-512_SSWU_NU*         | ❌ (+ missing non-uniform encoding) |
| curve25519   | curve25519*XMD:SHA-512_ELL2_RO*   | ❌ (curve specs need extending)     |
|              | curve25519*XMD:SHA-512_ELL2_NU*   | ❌ (+ missing non-uniform encoding) |
| edwards25519 | edwards25519*XMD:SHA-512_ELL2_RO* | ❌ (missing curve specs)            |
|              | edwards25519*XMD:SHA-512_ELL2_NU* | ❌ (+ missing non-uniform encoding) |
| curve448     | curve448*XOF:SHAKE256_ELL2_RO*    | ❌ (missing curve specs)            |
|              | curve448*XOF:SHAKE256_ELL2_NU*    | ❌ (+ missing non-uniform encoding) |
| edwards448   | edwards448*XOF:SHAKE256_ELL2_RO*  | ❌ (missing curve specs)            |
|              | edwards448*XOF:SHAKE256_ELL2_NU*  | ❌ (+ missing non-uniform encoding) |
| secp256k1    | secp256k1*XMD:SHA-256_SSWU_RO*    | ❌ (missing curve specs)            |
|              | secp256k1*XMD:SHA-256_SSWU_NU*    | ❌ (+ missing non-uniform encoding) |
| BLS12-381 G1 | BLS12381G1*XMD:SHA-256_SSWU_RO*   | ❌ (curve specs need extending)     |
|              | BLS12381G1*XMD:SHA-256_SSWU_NU*   | ❌ (+ missing non-uniform encoding) |
| BLS12-381 G2 | BLS12381G2*XMD:SHA-256_SSWU_RO*   | ❌ (curve specs need extending)     |
|              | BLS12381G2*XMD:SHA-256_SSWU_NU*   | ❌ (+ missing non-uniform encoding) |
|              |                                   |                                     |

# Abstract

This document specifies a number of algorithms for encoding or
hashing an arbitrary string to a point on an elliptic curve. This
document is a product of the Crypto Forum Research Group (CFRG) in
the IRTF.

# Introduction

Many cryptographic protocols require a procedure that encodes an
arbitrary input, e.g., a password, to a point on an elliptic curve.
This procedure is known as hashing to an elliptic curve, where the
hashing procedure provides collision resistance and does not reveal
the discrete logarithm of the output point. Prominent examples of
cryptosystems that hash to elliptic curves include password-
authenticated key exchanges [BM92] [J96] [BMP00] [p1363.2], Identity-
Based Encryption [BF01], Boneh-Lynn-Shacham signatures [BLS01]
[I-D.irtf-cfrg-bls-signature], Verifiable Random Functions [MRV99]
[I-D.irtf-cfrg-vrf], and Oblivious Pseudorandom Functions [NR97]
[I-D.irtf-cfrg-voprf].

Unfortunately for implementors, the precise hash function that is
suitable for a given protocol implemented using a given elliptic
curve is often unclear from the protocol's description. Meanwhile,
an incorrect choice of hash function can have disastrous consequences
for security.

This document aims to bridge this gap by providing a comprehensive
set of recommended algorithms for a range of curve types. Each
algorithm conforms to a common interface: it takes as input an
arbitrary-length byte string and produces as output a point on an
elliptic curve. We provide implementation details for each
algorithm, describe the security rationale behind each
recommendation, and give guidance for elliptic curves that are not
explicitly covered. We also present optimized implementations for
internal functions used by these algorithms.

Readers wishing to quickly specify or implement a conforming hash
function should consult Section 8, which lists recommended hash-to-
curve suites and describes both how to implement an existing suite
and how to specify a new one.

This document does not cover rejection sampling methods, sometimes
referred to as "try-and-increment" or "hunt-and-peck," because the
goal is to describe algorithms that can plausibly be computed in
constant time. Use of these rejection methods is NOT RECOMMENDED,
because they have been a perennial cause of side-channel
vulnerabilities. See Dragonblood [VR20] as one example of this
problem in practice, and see Appendix A for a further description of
rejection sampling methods.

This document represents the consensus of the Crypto Forum Research
Group (CFRG).

# Background

## Elliptic curves

The following is a brief definition of elliptic curves, with an
emphasis on important parameters and their relation to hashing to
curves. For further reference on elliptic curves, consult
[CFADLNV05] or [W08].

Let F be the finite field GF(q) of prime characteristic p > 3. (This
document does not consider elliptic curves over fields of
characteristic 2 or 3.) In most cases F is a prime field, so q = p.
Otherwise, F is an extension field, so q = p^m for an integer m > 1.
This document writes elements of extension fields in a primitive
element or polynomial basis, i.e., as a vector of m elements of GF(p)
written in ascending order by degree. The entries of this vector are
indexed in ascending order starting from 1, i.e., x = (x_1, x_2, ...,
x_m). For example, if q = p^2 and the primitive element basis is (1,
I), then x = (a, b) corresponds to the element a + b \* I, where x_1 =
a and x_2 = b. (Note that all choices of basis are isomorphic, but
certain choices may result in a more efficient implementation; this
document does not make any particular assumptions about choice of
basis.)

An elliptic curve E is specified by an equation in two variables and
a finite field F. An elliptic curve equation takes one of several
standard forms, including (but not limited to) Weierstrass,
Montgomery, and Edwards.

The curve E induces an algebraic group of order n, meaning that the
group has n distinct elements. (This document uses additive notation
for the elliptic curve group operation.) Elements of an elliptic
curve group are points with affine coordinates (x, y) satisfying the
curve equation, where x and y are elements of F. In addition, all
elliptic curve groups have a distinguished element, the identity
point, which acts as the identity element for the group operation.
On certain curves (including Weierstrass and Montgomery curves), the
identity point cannot be represented as an (x, y) coordinate pair.

For security reasons, cryptographic uses of elliptic curves generally
require using a (sub)group of prime order. Let G be such a subgroup
of the curve of prime order r, where n = h \* r. In this equation, h
is an integer called the cofactor. An algorithm that takes as input
an arbitrary point on the curve E and produces as output a point in
the subgroup G of E is said to "clear the cofactor." Such algorithms
are discussed in Section 7.

Certain hash-to-curve algorithms restrict the form of the curve
equation, the characteristic of the field, or the parameters of the
curve. For each algorithm presented, this document lists the
relevant restrictions.

The table below summarizes quantities relevant to hashing to curves:

| Symbol   | Meaning               | Relevance               |
| -------- | --------------------- | ----------------------- |
| F,q,p    | A finite field F of   | For prime fields, q =   |
|          | characteristic p      | p; otherwise, q = p^m   |
|          | and #F = q = p^m.     | and m>1.                |
| -------- | --------------------- | ----------------------- |
| E        | Elliptic curve.       | E is specified by an    |
|          |                       | equation and a field    |
|          |                       | F.                      |
| -------- | --------------------- | ----------------------- |
| n        | Number of points on   | n = h \* r, for h and   |
|          | the elliptic curve    | r defined below.        |
|          | E.                    |                         |
| -------- | --------------------- | ----------------------- |
| G        | A prime-order         | Destination group to    |
|          | subgroup of the       | which byte strings      |
|          | points on E.          | are encoded.            |
| -------- | --------------------- | ----------------------- |
| r        | Order of G.           | r is a prime factor     |
|          |                       | of n (usually, the      |
|          |                       | largest such factor).   |
| -------- | --------------------- | ----------------------- |
| h        | Cofactor, h >= 1.     | An integer satisfying   |
|          |                       | n = h \* r.             |

## Terminology

In this section, we define important terms used throughout the
document.

### Mappings

A mapping is a deterministic function from an element of the field F
to a point on an elliptic curve E defined over F.

In general, the set of all points that a mapping can produce over all
possible inputs may be only a subset of the points on an elliptic
curve (i.e., the mapping may not be surjective). In addition, a
mapping may output the same point for two or more distinct inputs
(i.e., the mapping may not be injective). For example, consider a
mapping from F to an elliptic curve having n points: if the number of
elements of F is not equal to n, then this mapping cannot be
bijective (i.e., both injective and surjective) since the mapping is
defined to be deterministic.

Mappings may also be invertible, meaning that there is an efficient
algorithm that, for any point P output by the mapping, outputs an x
in F such that applying the mapping to x outputs P. Some of the
mappings given in Section 6 are invertible, but this document does
not discuss inversion algorithms.

### Encodings

Encodings are closely related to mappings. Like a mapping, an
encoding is a function that outputs a point on an elliptic curve. In
contrast to a mapping, however, the input to an encoding is an
arbitrary-length byte string.

This document constructs deterministic encodings by composing a hash
function Hf with a deterministic mapping. In particular, Hf takes as
input an arbitrary string and outputs an element of F. The
deterministic mapping takes that element as input and outputs a point
on an elliptic curve E defined over F. Since Hf takes arbitrary-
length byte strings as inputs, it cannot be injective: the set of
inputs is larger than the set of outputs, so there must be distinct
inputs that give the same output (i.e., there must be collisions).
Thus, any encoding built from Hf is also not injective.

Like mappings, encodings may be invertible, meaning that there is an
efficient algorithm that, for any point P output by the encoding,
outputs a string s such that applying the encoding to s outputs P.
The instantiation of Hf used by all encodings specified in this
document (Section 5) is not invertible. Thus, the encodings are also
not invertible.

In some applications of hashing to elliptic curves, it is important
that encodings do not leak information through side channels. [VR20]
is one example of this type of leakage leading to a security
vulnerability. See Section 10.3 for further discussion.

### Random oracle encodings

A random-oracle encoding satisfies a strong property: it can be
proved indifferentiable from a random oracle [MRH04] under a suitable
assumption.

Both constructions described in Section 3 are indifferentiable from
random oracles [MRH04] when instantiated following the guidelines in
this document. The constructions differ in their output
distributions: one gives a uniformly random point on the curve, the
other gives a point sampled from a nonuniform distribution.

A random-oracle encoding with a uniform output distribution is
suitable for use in many cryptographic protocols proven secure in the
random oracle model. See Section 10.1 for further discussion.

### Serialization

A procedure related to encoding is the conversion of an elliptic
curve point to a bit string. This is called serialization, and is
typically used for compactly storing or transmitting points. The
inverse operation, deserialization, converts a bit string to an
elliptic curve point. For example, [SEC1] and [p1363a] give standard
methods for serialization and deserialization.

Deserialization is different from encoding in that only certain
strings (namely, those output by the serialization procedure) can be
deserialized. In contrast, this document is concerned with encodings
from arbitrary strings to elliptic curve points. This document does
not cover serialization or deserialization.

### Domain separation

Cryptographic protocols proven secure in the random oracle model are
often analyzed under the assumption that the random oracle only
answers queries associated with that protocol (including queries made
by adversaries) [BR93]. In practice, this assumption does not hold
if two protocols use the same function to instantiate the random
oracle. Concretely, consider protocols P1 and P2 that query a random
oracle RO: if P1 and P2 both query RO on the same value x, the
security analysis of one or both protocols may be invalidated.

A common way of addressing this issue is called domain separation,
which allows a single random oracle to simulate multiple, independent
oracles. This is effected by ensuring that each simulated oracle
sees queries that are distinct from those seen by all other simulated
oracles. For example, to simulate two oracles RO1 and RO2 given a
single oracle RO, one might define

RO1(x) := RO("RO1" || x)
RO2(x) := RO("RO2" || x)

where || is the concatenation operator. In this example, "RO1" and
"RO2" are called domain separation tags; they ensure that queries to
RO1 and RO2 cannot result in identical queries to RO, meaning that it
is safe to treat RO1 and RO2 as independent oracles.

In general, domain separation requires defining a distinct injective
encoding for each oracle being simulated. In the above example,
"RO1" and "RO2" have the same length and thus satisfy this
requirement when used as prefixes. The algorithms specified in this
document take a different approach to ensuring injectivity; see
Section 5.3 and Section 10.7 for more details.
