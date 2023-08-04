# Attacker Capabilities
There are different types of attackers based on their participation in
the protocol.
## Passive Attackers
A passive attacker (aka "honest-but-curious" or "semi-honest"
attacker) has the corrupted parties participating in the protocol in
an honest way and attempts to gain an advantage after the fact solely
based on the information gained from the honest party views,
i.e. their inputs, internal state and received messages during the
protocol and their outputs. In practice guarantees against these types
of attackers offer only weak assurance in the security of the protocol
beyond safeguarding against accidental information leakages.

## Active Attackers
Active attackers are allowed to disrupt the protocol by having
corrupted parties send arbitrary malicious protocol messages. In terms
of giving guarantees this is the preferred attacker model.

## Covert Attackers
Covert attackers may perform some active disruptions, as long as the
probability of detection for this malicious behaviour remains below a
certain threshold. Conversely security against this type of attacker
implies that cheating behaviour will be detected with some (high)
probability that can be chosen depending on the application.

# Corruption Strategies
Different notions also arise from the question of when adversarial
corruptions occur in the protocol run.

## Selective Corruptions
A selective attacker has to commit to the corrupted parties before the
protocol is run. Then the protocol is run with fixed sets of honest
and corrupted parties.

## Adaptive Corruptions
An adaptive adversary can continue to corrupt any protocol parties
even during the run of the protocol, depending on its joint view from
the parties it has already corrupted. Parties that have at some point
been corrupted will stay so for the rest of the protocol run.

## Proactive Security
This is an extension of the adaptive case, where a once corrupted
party can become honest again, meaning that the adversary only has
access to the portion of the view of that party for the duration of
the corruption.
