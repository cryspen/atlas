# Security Requirements for MPC protocol

The five most important security requirements for secure MPC protocols
are as follows:

1. **Correctness**: The compuation results for honest parties should
   always be the correct ones with respect to the inputs provided by
   the parties.
2. **Privacy**: The parties learn nothing beyond (their part of) the
   result of the computation.
3. **Independence of Inputs**: Adversarial parties cannot choose their
   inputs dependent on inputs of honest parties. This is not implied
   by privacy, since you could imagine a protocol where an attacker
   can e.g. replay an honest parties encrypted input message to the
   other parties as their own input message but through some
   malleability of the used encryption scheme alter the encrypted
   value without having to know it, for instance incrementing it.
4. **Guaranteed Output Delivery**: The protocol should not allow
   Denial-of-Service type attacks, where honest parties do not receive
   the protocol outputs.
5. **Fairness**: If adversarial parties receive their outputs, then
   honest parties must also have received their outputs. This is
   implied by guaranteed output delivery, but the converse does not
   hold, since complete denial-of-service results in a fair outcome,
   i.e. no-one gets their output.
   
   
