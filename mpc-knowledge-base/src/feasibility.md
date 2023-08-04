# Feasibility and Degrees of Corruption

Although, in principle, secure multiparty computation can be achieved
for any function there are is some degradation in the achievable
guarantees as the proportion of corrupted parties among the protocol
participants rises and the requirements on the protocol environment
rise as well.

* The most favorable case is when less than \\(\frac{1}{3}\\) of
  participants in the protocol are dishonest. In this case MPC with
  fairness and guaranteed output delivery can be achieved under
  computational assumptions assuming a synchronous point-to-point
  network of authenticated channels between participants. The
  computational assumptions can be dropped (i.e. the result hold
  information-theoretically) if the channels are assumed to be
  private.
  
* More generally in the case of an honest majority (less than
  \\(\frac{1}{2}\\) of participants are corrupted) fairness and
  guaranteed output delivery can be achieved given the existence of a
  broadcast channel for all parties.
  
* In case of a dishonest majority, although correct, private and
  input-indepented MPC can still be achieved, fairness and guaranteed
  output delivery cannot be guaranteed in general.
