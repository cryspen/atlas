## DhKem25519 HkdfSha256 ChaCha20Poly1305

`Seal` and `Open` are called with a 128 byte payload and 48 bytes additional data.

|                  | hpke-rs (evercrypt) | hpke-rs (rust crypto) | hacspec (evercrypt) | rust-hpke |
| ---------------- | ------------------- | --------------------- | ------------------- | --------- |
| **Base**         |                     |                       |                     |           |
| Setup Sender     | 133.62μs            | 64.48μs               | 129.81μs            | 118.73μs  |
| Setup Receiver   | 81.074μs            | 61.34μs               | 85.06μs             | 55.30μs   |
| Seal             | 1.05μs              | 0.67μs                | 1.69μs              | 0.58μs    |
| Open             | 1.08μs              | 0.72μs                | 1.63μs              | 0.57μs    |
| Single-Shot Seal | 85.23μs             | 63.80μs               | 92.30μs             |           |
| Single-Shot Open | 81.04μs             | 61.11μs               | 87.19μs             |           |
| **Auth**         |                     |                       |                     |           |
| Setup Sender     | 146.75μs            | 112.15μs              | 153.26μs            | 104.95μs  |
| Setup Receiver   | 112.16μs            | 96.93μs               | 116.81μs            | 55.33μs   |
| Seal             | 1.00μs              | 0.66μs                | 1.61μs              |           |
| Open             | 1.04μs              | 0.69μs                | 1.63μs              |           |
| Single-Shot Seal | 146.54μs            | 111.62μs              | 157.18μs            |           |
| Single-Shot Open | 112.25μs            | 96.60μs               | 118.80μs            |           |
| **Psk**          |                     |                       |                     |           |
| Setup Sender     | 85.52μs             | 64.60μs               | 90.97μs             | 69.62μs   |
| Setup Receiver   | 81.04μs             | 61.36μs               | 85.78μs             | 91.04μs   |
| Seal             | 1.04μs              | 0.67μs                | 1.61μs              |           |
| Open             | 1.04μs              | 0.71μs                | 1.65μs              |           |
| Single-Shot Seal | 85.49μs             | 63.95μs               | 92.83μs             |           |
| Single-Shot Open | 81.18μs             | 61.33μs               | 88.53μs             |           |
| **AuthPsk**      |                     |                       |                     |           |
| Setup Sender     | 146.92μs            | 112.16μs              | 153.33μs            | 105.11μs  |
| Setup Receiver   | 112.72μs            | 96.89μs               | 117.40μs            | 90.85μs   |
| Seal             | 1.03μs              | 0.67μs                | 1.59μs              |           |
| Open             | 1.02μs              | 0.69μs                | 1.60μs              |           |
| Single-Shot Seal | 146.764μs           | 111.67μs              | 154.87μs            |           |
| Single-Shot Open | 112.52μs            | 96.83μs               | 118.77μs            |           |
