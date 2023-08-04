# Secret Sharing
To implement a general purpose MPC protocol in the semi-honest
setting, all that is required beyond the network infrastructure
discussed in the previous section is a homomorphic secret sharing
scheme.

An example of such a scheme is Shamir's secret sharing scheme.

## Basic Definition
A \\((t, n)\\)-secret sharing scheme is a protocol where a party can
compute from their secret input a set of \\(n\\) shares such that the
individual shares do not reveal the secret input:

\\[\mathtt{generate-shares}(\mathit{secret}) = (\mathit{share}_1, \ldots, '\mathit{share}_n).\\]

Only if a threshold of \\(t \leq n\\) shares is united can the
secret input be reconstructed:

\\[\mathtt{reconstruct-secret}(\\{\mathit{share_i}\\}_{i \in \mathcal{I}}) =\mathit{secret},\\]

where \\(\mathcal{I} \subset \\{0,\ldots,n\\}\\) and \\(|\mathcal{I}| = t\\).

## Computing on Shares

There are secret sharing schemes that allow basic arithmetic to be
performed on shares, i.e. shares of different secrets can be added and
multiplied such that a reconstruction based on suitably many addition
/ multiplication shares results in the addition / multiplication of
the original secrets that were shared.

**TODO: Make this more formal here**

