# Introduction & Overview

For a condensed overview of the most important concepts consider
[Secure Multiparty Computation](https://eprint.iacr.org/2020/300) by
Yehuda Lindell. The following sections attempt a further summary.

Consider a function \\(f: X^N \rightarrow Y^N\\), where \\(X\\) is a
set of inputs and \\(Y\\) is a set of outputs.  The main goal of
secure multiparty computation is for a set of parties \\(\mathcal{P} =
\\{\mathcal{P}_1, \mathcal{P}_2, \ldots, \mathcal{P}_N\\}\\) who each
hold a private input \\(x_i \in X\\) for \\(i \in \\{1, \ldots,
N\\}\\) to jointly compute \\[f(x_1, x_2, \ldots, x_N)=(f_1(x_1,
\ldots, x_N), \ldots, f_N(x_1, \ldots, x_N))\\] on their inputs
without revealing their inputs to the other parties.Usually, each
party \\(\mathcal{P}_i\\) receives just their output \\(f_i(x_1, x_2,
\ldots, x_N)\\), although it could well be that all \\(f_i\\) are
actually the same.

An MPC protocol should achieve this (and more, see below) even if a
subset of the protocol parties is under the control of an adversarial
entity, or attacker.

There are some axis along which concrete MPC schemes and
implementations differ, in brief:
  * How many parties are there? 
	* The case of just two parties is usually different from the more
      general case.
	* In the general case, how does the protocol deal with
      communication between a large number of parties?
  * What kind of function is \\(f\\) and how is it expressed in the
    scheme? There are MPC systems for joint evaluation of any function
    which can be expressed as a boolean or arithmetic circuit, while
    others are restricted to very specific functionalities. Often the
    more general schemes are outperformed by specialized schemes.
  * What is our notion of **security**? As usual in cryptographic
    settings we have to consider possible attacker goals as well as
    capabilities we afford an attacker.
  * Usually the attacker is assumed to have _corrupted_ some subset
	of the protocol parties. We can think about restrictions on the
	attackers ability to corrupt party members, e.g. for any of the
	security guarantees to hold we require a threshold of honest
	parties, or if the scheme is implemented in a multi-round protocol
	we should think about corruptions at different stages in the
	protocol and whether the adversary has to commit beforehand to
	which parties it wants to corrupt or can decide based on the
	development of the protocol to any given point.
  * An attacker might have different goals in disrupting the
	computation: Learn private inputs, deny the output to honest
	parties, falsify the output that honest parties receive, etc.

A more in-depth introduction is found in [A Pragmatic Introduction
to Secure Multi-Party Computation](https://securecomputation.org)
written by David Evans, Vladimir Kolesnikov and Mike Rosulek.

A growing collection of real world deployments of MPC systems is
maintained at UC Berkeley: [MPC
Deployments](https://mpc.cs.berkeley.edu/).

