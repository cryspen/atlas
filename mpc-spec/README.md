# Specification of an MPC engine

This project contains the work in progress specification of a multi-party
computation engine based on the publication:

> Xiao Wang, Samuel Ranellucci, and Jonathan Katz. 2017. Global-Scale Secure
> Multiparty Computation. In Proceedings of the 2017 ACM SIGSAC Conference on
> Computer and Communications Security (CCS '17). Association for Computing
> Machinery, New York, NY, USA, 39–56. <https://doi.org/10.1145/3133956.3133979>

A full description of the scheme is available at [WRK17][1].

Differences to the scheme described in WRK17 are as follows:

- WRK17 considers circuits made up of AND and XOR gates, leaving NOT gates
  implicit (as each party can evaluate them locally by XORing with constant
  `1`). For the sake of a more natural presentation, we have chosen to include
  NOT gates explicitely in our circuit description.

[1]: https://eprint.iacr.org/2017/189.pdf
