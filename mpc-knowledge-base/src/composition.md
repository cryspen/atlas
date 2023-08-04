# Compositional Security

An MPC protocol can be used as a subprotocol for a larger protocol,
and via a property called _modular composition_ will behave like the
execution of the protocol ideal functionality by a third party.

This holds in the case that the protocol is run on its own, i.e. no
other protocols run concurrently, the so called **stand-alone
setting**.
 
Security may not hold if the protocol is run concurrently with other
(secure or insecure) protocols, even instances of itself. In order to
argue security in these cases, the most common approach is to employ
the _universal composability_ framework. If proven secure in that
framework, the protocol remains secure under arbitrary concurrent
compositions.
