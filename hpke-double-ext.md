# Introduction

In the ScrambleDB system for oblivious data pseudonymization, one
party serves as an relay for batches of encrypted values intended to
reach a third party. It is required that the outgoing ciphertexts
cannot be linked to the incoming ciphertexts by an outside
(unprivileged) observer, i.e. it should be infeasible to tell whether
a given part of the outgoing batch encrypts the same value as some
part of the incoming batch.

One possiblity to realize this would be decryption and re-encryption
of the ciphertext at the relay using fresh nonces. This will result in
fresh, unlinkable ciphertexts. However, it requires the relay to be
able to decrypt incoming messages. In ScrambleDB at least, the relay
should stay oblivious to the encrypted data it relays, ruling out this
approach.

There are several public key encryptions schemes which can realize
this functionality instead via the ability to rerandomize ciphertexts
in a way such that rerandomization essentially samples a fresh
ciphertext from the set of possible ciphertexts encrypting the given
message. Because of the underlying ciphertext-indistinguishability of
these encryption schemes a freshly sampled encryption of a message is
indistinguishable from an encryption of any other incoming
message. Examples for such schemes include the ElGamal and Pallier
public key encryption systems.

In practice, public key encryption is often used in a hybrid fashion
such that the bulk of the content is encrypted using fast symmetric
encryption using a PKE-encapsulated shared secret. A straightforward
adaptation of the rerandomization approach is not possible in the
hybrid setting, since the ciphertext as a whole does not offer the
algebraic structure that is fundamentally necessary to this approach.

To address the issues outlined above we propose double hybrid public
key encryption as a solution to practical, rerandomizable encryption
of arbitrary data. In short, in out proposal a ciphertext is
transformed into a new ciphertext, such that the new ciphertext should
be indistinguishable from a analogously transformed different original
ciphertext. See [Security Notion] for further details on the
desired properties.

# Conventions and Definitions

In addition to the conventions and requirements for HPKE we define a
third party beside Sender (S) and Receiver (R), namely the Relay (X).

## Double HPKE Mode

We define an additional HPKE Mode identifier `mode_double` with value
`0x04`.

## Ciphertext Levels

We consider two levels of ciphertexts:

-   Level-1 ciphertexts are the result of encrypting the message once
    towards the receiver using a sender encryptiion context as specified
    below.
-   Level-2 ciphertexts are the result of encrypting a level-1
    ciphertext one more time using a relay encryption context as
    specified below.

Which level a ciphertext is does not need to be hidden. In fact we
require the following function to determine what level a ciphertext is at:

    def ct_level(ct):
        if ct is a level-1 ciphertext:
            return 1
        if ct is a level-2 ciphertext:
            return 2


# Double HPKE

For simplicity we define our double encryption extension only for the
basic case of encryption to a public key. Encryption based on a
pre-shared key (PSK) as well as authenticated encryption using either just
an asymmetric key or an asymmetric key and PSK are left unspecified.


## Three Party Encryption Context

The sender can create its encryption context in the same way as in 
standard HPKE:

    def SetupDoubleS(pkR, info):
        shared_secret, enc = Encap(pkR)
        return enc, KeySchedule(mode_double, shared_secret, info,
                                default_psk, default_psk_id)

For the relay, context generation is the same as for the sender

    def SetupDoubleX(pkR, info):
        shared_secret, enc = Encap(pkR)
        return enc, KeySchedule(mode_double, shared_secret, info,
                                default_psk, default_psk_id)

The receiver has to keep track of both key schedules now:

    def SetupDoubleR(encS, encX, skR, info):
        shared_secret_S = Decap(encS, skR)
        shared_secret_X = Decap(encX, skR)
    
        key_schedule_S = KeySchedule(mode_double, shared_secret_S, info,
                                default_psk, default_psk_id)
    
        key_schedule_R = KeySchedule(mode_double, shared_secret_R, info,
                                default_psk, default_psk_id)
    
        return (key_schedule_S, key_schedule_R)

## Encryption, Double Encryption and Decryption

Creation of level-1 ciphertexts, i.e. regular encryption, from sender to receiver is exactly the same as in standard HPKE:

    def ContextS.Seal(aad, pt):
        ct = Seal(self.key, self.ComputeNonce(self.seq), aad, pt)
        self.IncrementSeq()
        return ct

Level-2 ciphertexts are created by encrypting a level-1 ciphertext one more time using the relays encryption context:

    def ContextX.ReSeal(aad, ct):
        if ct_level(ct) != 1:
            raise InvalidParameters
        cct = Seal(self.key, self.ComputeNonce(self.seq), aad, ct)
        self.IncrementSeq()
        return cct

Decryption is only defined on level-2 ciphertexts:

    def ContextR.Open(aad, cct):
        if ct_level(cct) != 2:
            raise InvalidParameters
        ct = Open(self.key, self.ComputeNonce(self.seq), aad, cct)
        pt = Open(self.key, self.ComputeNonce(self.seq), aad, ct)
        if pt == OpenError:
          raise OpenError
        self.IncrementSeq()
        return pt
        
## Single-Shot Double HPKE
HPKE Double encryption can already be implemented using the single-shot
basic mode API provided by standard HPKE. We specify the following
serialization/deserialization scheme for HPKE ciphertexts:

```text
    def SerializeHPKECt(enc, ct):
        return I2OSP(len(enc), 4) || I2OSP(len(ct), 4) || enc || ct
        
    def DeserializeHPKECt(bytes):
        len_enc = OS2IP(bytes[0..4])
        len_ct = OS2IP(bytes[4..8])
        return (enc = bytes[8..8 + len_enc], ct = bytes [8 + len_enc ... 8 + len_enc + len_ct])
```

### Level-1 Encryption
```text
    def SealDouble(pkR, info, aad, pt, ...):
        enc, ct = SealBase(pkR, info, aad, ptxt, ...)
        hpke_serialized = SerializeHPKECt(enc,ct)
        return hpke_serialized
```

### Level-2 Encryption
```text
    def ReSealDouble(pkR, info, aad, hpke_serialized, ...):
        enc, ct = SealBase(pkR, info, aad, hpke_serialized, ...)
        return (enc, ct)
```

### Decryption
```text
    def OpenDouble(enc, skR, info-1, aad-1, info-2, aad-2, ct, ...):
        hpke_serialized = OpenBase(enc, skR, info-2, aad-2, ct, ...)
        (enc_inner, ct_inner) = DeserializeHPKECt(hpke_serialized)
        pt = OpenBase(enc_inner, skR, info-1, aad-1, ct_inner, ...)
        return pt
```

# Security Notions

In conventional game-based fashion, we define the desired
indistinguishability property as follows:

Suppose we have access to honestly generated encryption / decryption
context `ContextX` and recipient encryption key `pkR`. We define the following oracles.

    def LevelTwoEncrypt(ct):
        if ct_level(ct) != 1:
            abort
        return ContextX.ReSeal(ct)

Given access to the oracles above we require that an adversary has at
most negligible chance of success (result: `true`) in the following game:

    def IND-ReSeal():
        Generate ContextX, ContextR
        (ct_0, ct_1) = Adversary("choose", pkR)
        for i in {0,1}:
            if ct_level(ct_i) != 1:
                return false
            cct_i = ContextX.ReSeal(m_i)
         b = random_bit()
         b_guess = Adversary("guess", cct_b)
         return b == b_guess

Note that the adversary provides the level-one ciphertexts.
