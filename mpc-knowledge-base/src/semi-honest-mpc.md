# MPC based on secret sharing

Given a homomorphic secret sharing scheme as described above we can
construct an MPC protocol for any computable function, since any such
function can be expressed in terms of an arithmetic circuit using
additions and multiplications. It is assumed that all parties agree on
the function to be computed and its representation as an arithmetic
circuit.

The resulting scheme can be shown to be secure against semi-honest
adversaries, but security breaks down in the malicious case, where
other techniques are necessary.

## Phase 1: Input Share Construction
All parties compute a secret sharing of their private input and
distribute the individual shares to the other parties.

## Phase 2: Circuit Evaluation
The parties evaluate the circuit gate by gate. Depending on the secret
sharing scheme that is used some types of gates can be evaluated
locally, while other types of gates require rounds of communication
with the other parties. Using Shamir's scheme, for instance, addition
can be performed locally, while multiplication requires parties to
perform further sharing rounds.

## Phase 3: Output Reconstruction
After the circuit has been evaluated, all parties have shares of the
values on the output wires of the circuit. Broadcasting their shares
allows all parties to reconstruct all output wire values. Party
outputs can be restricted to certain wires by selectively distributing
output wire shares.
