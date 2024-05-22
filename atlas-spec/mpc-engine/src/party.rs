//! This module defines the behaviour of protocol parties in the different
//! phases of the protocol.

use hacspec_lib::Randomness;

use crate::{
    circuit::Circuit,
    messages::{Message, MessagePayload, SubMessage},
    primitives::{
        auth_share::{AuthBit, Bit, BitID, BitKey},
        commitment::{Commitment, Opening},
        mac::{
            generate_mac_key, hash_to_mac_width, mac, verify_mac, xor_mac_width, Mac, MacKey,
            MAC_LENGTH,
        },
    },
    utils::ith_bit,
    Error, STATISTICAL_SECURITY,
};

use std::sync::mpsc::{self, Receiver, Sender};

/// Additional bit authentications computed for malicious security checks.
const SEC_MARGIN_BIT_AUTH: usize = 2 * STATISTICAL_SECURITY * 8;
/// Additional cost of authenticating a number of bits into authenticated shares.
const SEC_MARGIN_SHARE_AUTH: usize = STATISTICAL_SECURITY * 8;

#[derive(Debug)]
/// A type for tracking the current protocol phase.
pub enum ProtocolPhase {
    /// Before the protocol has begun
    PreInit,
    /// Function-independent pre-processing
    Init,
}

/// Collects all party communication channels.
///
/// It includes
/// - `listen`: The party's own message receiver handle
/// - `evaluator`: The sender handle for the designated evaluator party
/// - `parties`: All other parties' sender handles, ordered by their `id`s
/// - `broadcast`: The sender handle of the broadcast utility
/// - `id`: The owning parties `id`
pub struct ChannelConfig {
    pub(crate) listen: Receiver<Message>,
    pub(crate) evaluator: Sender<Message>,
    pub(crate) parties: Vec<Sender<Message>>,
    pub(crate) broadcast: Sender<Message>,
    /// The channel config is for the party of this ID.
    pub id: usize,
}

/// A struct defining protocol party state during a protocol execution.
#[allow(dead_code)] // TODO: Remove this later.
pub struct Party {
    bit_counter: usize,
    /// The party's numeric identifier
    id: usize,
    /// The number of parties in the MPC session
    num_parties: usize,
    /// The channel configuration for communicating to other protocol parties
    channels: ChannelConfig,
    /// The global MAC key for authenticating wire value shares
    global_mac_key: MacKey,
    /// The circuit to be evaluated
    circuit: Circuit,
    /// A local source of random bits and bytes
    entropy: Randomness,
    /// Pool of pre-computed authenticated bits
    abit_pool: Vec<AuthBit>,
    /// Tracks the current phase of protocol execution
    current_phase: ProtocolPhase,
    /// Whether to log events
    enable_logging: bool,
    /// Incremental counter for ordering logs
    log_counter: u128,
}

#[allow(dead_code)] // TODO: Remove this later.
impl Party {
    /// Initialize an MPC party.
    ///
    /// This generates the party's global MAC key and sets the protocol phase to
    /// `PreInit`.
    pub fn new(
        channels: ChannelConfig,
        circuit: &Circuit,
        logging: bool,
        mut entropy: Randomness,
    ) -> Self {
        Self {
            bit_counter: 0,
            id: channels.id,
            num_parties: channels.parties.len(),
            channels,
            global_mac_key: generate_mac_key(&mut entropy),
            circuit: circuit.clone(),
            entropy,
            abit_pool: Vec::new(),
            current_phase: ProtocolPhase::PreInit,
            log_counter: 0,
            enable_logging: logging,
        }
    }

    /// Broadcast a `value` and receive other parties' broadcasted values in
    /// turn.
    ///
    /// Broadcast works using the broadcast relay utility:
    /// - In a first step, compute a cryptographic commitment on `value` and
    /// send that individually to all other parties.
    /// - Then send the commitment opening to the broadcast relay.
    /// - Finally, receive the other parties commitment openings from the
    ///   broadcast relay and use them to open their commitments to their
    ///   values.
    ///
    /// Since every party can only send one opening value to the broadcast
    /// relay, which is assumed to be trusted in distributing the received
    /// openings faithfully, it is ensured that every commitment is opened with
    /// the opening information. Therefore, because the commitments are binding,
    /// if a malicious party sends differing commitments to different parties at
    /// least one opening must fail.
    ///
    /// In a non-blackbox way we can also see that parties cannot chose their
    /// broadcast values dependent on other parties' values: Beside being
    /// hiding, the Random Oracle commitment we use also does not allow any
    /// homomorphic operations on commitment values, so even given many
    /// commitments from other parties a malicious party should not be able to
    /// chose their commitment in a way that the committed value is dependent on
    /// other parties' committed values.
    fn broadcast(&mut self, value: &[u8]) -> Result<Vec<(usize, Vec<u8>)>, Error> {
        // send/receive commitment to/from all parties
        let domain_separator = format!("Broadcast-{}", self.id);
        let (commitment, opening) =
            Commitment::new(value, domain_separator.as_bytes(), &mut self.entropy);

        let mut received_commitments = Vec::new();
        // Expect earlier parties' commitments.
        for _i in 0..self.id {
            let commitment_msg = self
                .channels
                .listen
                .recv()
                .expect("all parties should be online");
            if let MessagePayload::BroadcastCommitment(received_commitment) = commitment_msg.payload
            {
                debug_assert_eq!(commitment_msg.to, self.id);
                received_commitments.push((commitment_msg.from, received_commitment));
            } else {
                return Err(Error::UnexpectedMessage(commitment_msg));
            }
        }

        // All earlier commitments have been received, so it is the party's turn
        // to send messages to everyone, except itself.
        for i in 0..self.num_parties {
            if i == self.id {
                continue;
            }

            self.channels.parties[i]
                .send(Message {
                    from: self.id,
                    to: i,
                    payload: MessagePayload::BroadcastCommitment(commitment.clone()),
                })
                .expect("all parties should be online");
        }

        // Wait for the commitments sent by later parties.
        for _i in self.id + 1..self.num_parties {
            let commitment_msg = self
                .channels
                .listen
                .recv()
                .expect("all parties should be online");
            if let MessagePayload::BroadcastCommitment(received_commitment) = commitment_msg.payload
            {
                debug_assert_eq!(commitment_msg.to, self.id);
                received_commitments.push((commitment_msg.from, received_commitment));
            } else {
                return Err(Error::UnexpectedMessage(commitment_msg));
            }
        }

        self.sync().expect("synchronization should have succeeded");

        // Send the opening to the broadcast relay.
        self.channels
            .broadcast
            .send(Message {
                from: self.id,
                to: self.id,
                payload: MessagePayload::BroadcastOpening(opening),
            })
            .expect("all parties should be online");

        // Receive n-1 openings from the broadcast relay.
        let mut received_values = Vec::new();
        for _i in 0..self.num_parties - 1 {
            let opening_msg = self
                .channels
                .listen
                .recv()
                .expect("all parties should be online");
            if let MessagePayload::BroadcastOpening(ref received_opening) = opening_msg.payload {
                let received_commitment = &received_commitments
                    .iter()
                    .find(|(received_from, _)| *received_from == opening_msg.from)
                    .expect("should get opening from all parties")
                    .1;
                let received_value = received_commitment.open(received_opening)?;
                received_values.push((opening_msg.from, received_value));
            } else {
                return Err(Error::UnexpectedMessage(opening_msg));
            }
        }

        self.sync().expect("synchronization should have succeeded");
        Ok(received_values)
    }

    /// Broadcast three commitments for the share authentication malicious security check.
    fn broadcast_commitments(
        &mut self,
        commitment_0: Commitment,
        commitment_1: Commitment,
        commitment_macs: Commitment,
    ) -> Result<Vec<(usize, Commitment, Commitment, Commitment)>, Error> {
        let mut commitment_bytes = Vec::new();
        commitment_bytes.extend_from_slice(&commitment_0.as_bytes());
        commitment_bytes.extend_from_slice(&commitment_1.as_bytes());
        commitment_bytes.extend_from_slice(&commitment_macs.as_bytes());

        let other_commitment_bytes = self.broadcast(&commitment_bytes)?;
        let mut results = Vec::new();
        for j in 0..self.num_parties {
            if j == self.id {
                continue;
            }
            let (_party, their_commitment_bytes) = other_commitment_bytes
                .iter()
                .find(|(party, _)| *party == j)
                .expect("should have received commitments from every other party");
            let (their_commitment_0, rest) = Commitment::from_bytes(their_commitment_bytes)?;
            let (their_commitment_1, rest) = Commitment::from_bytes(&rest)?;
            let (their_commitment_macs, rest) = Commitment::from_bytes(&rest)?;
            debug_assert!(rest.is_empty());
            results.push((
                j,
                their_commitment_0,
                their_commitment_1,
                their_commitment_macs,
            ))
        }

        Ok(results)
    }

    /// Broadcast opening values for the share authentication malicious security check.
    fn broadcast_opening(&mut self, opening: Opening) -> Result<Vec<(usize, Opening)>, Error> {
        let other_opening_bytes = self.broadcast(&opening.as_bytes())?;
        let mut results = Vec::new();
        for j in 0..self.num_parties {
            if j == self.id {
                continue;
            }
            let (_party, their_opening_bytes) = other_opening_bytes
                .iter()
                .find(|(party, _)| *party == j)
                .expect("should have received openings from all other parties");
            results.push((j, Opening::from_bytes(their_opening_bytes)?));
        }
        Ok(results)
    }

    /// Return `true`, if the party is the designated circuit evaluator.
    fn is_evaluator(&self) -> bool {
        self.id == 0
    }

    /// Send a message to the evaluator.
    fn send_to_evaluator(&mut self, message: Message) {
        self.channels
            .evaluator
            .send(message)
            .expect("evaluator should be online");
    }

    /// Jointly compute `len` bit authentications.
    ///
    /// Internally generates `len +  SEC_MARGIN_BIT_AUTH` bit
    /// authentications for each other party, of which all but `len` are
    /// discarded after performing statistical checks for malicious security.
    /// After this point the guarantee is that a pair-wise consistent
    /// `global_mac_key` was used in all bit-authentications between two
    /// parties.
    fn precompute_abits(&mut self, len: usize) -> Result<Vec<AuthBit>, Error> {
        self.log(&format!("{len} bit authentications requested, require an additional {SEC_MARGIN_BIT_AUTH} bit authentications for malicious security."));
        let len_unchecked = len + SEC_MARGIN_BIT_AUTH;

        // 1. Generate `len_unchecked` random local bits for authenticating.
        let random_bytes = self
            .entropy
            .bytes(len_unchecked / 8 + 1)
            .expect("sufficient randomness should have been provided externally")
            .to_owned();
        let mut bits = Vec::new();

        for i in 0..len_unchecked {
            bits.push(Bit {
                id: self.fresh_bit_id(),
                value: ith_bit(i, &random_bytes),
            })
        }

        // 2. Obliviously get MACs on all local bits from every other party and obliviously provide MACs on
        //    their local bits.
        let mut authenticated_bits = Vec::new();
        for (bit_index, bit) in bits.into_iter().enumerate() {
            let mut computed_keys: Vec<BitKey> = Vec::new();
            let mut received_macs = Vec::new();

            // Obliviously authenticate local bits of earlier parties.
            for bit_holder in 0..self.id {
                let computed_key = self.provide_bit_authentication(bit_holder)?;
                computed_keys.push(computed_key)
            }

            // Obliviously obtain MACs on the current bit from all other parties.
            for authenticator in 0..self.num_parties {
                if authenticator == self.id {
                    continue;
                }

                let received_mac: Mac = self.obtain_bit_authentication(authenticator, &bit)?;
                received_macs.push((authenticator, received_mac));
            }

            // Obliviously authenticate local bits of later parties.
            for bit_holder in self.id + 1..self.num_parties {
                let computed_key = self.provide_bit_authentication(bit_holder)?;
                computed_keys.push(computed_key)
            }

            self.sync().expect("synchronization should have succeeded");

            self.log(&format!(
                "Completed a bit authentication [{}/{}]",
                bit_index + 1,
                len_unchecked
            ));

            authenticated_bits.push(AuthBit {
                bit,
                macs: received_macs,
                mac_keys: computed_keys,
            })
        }

        self.sync().expect("synchronization should have succeeded");

        // 3. Perform the statistical check for malicious security of the
        //    generated authenticated bits. Failure indicates buggy bit
        //    authentication or cheating.
        self.bit_auth_check(&authenticated_bits)
            .expect("bit authentication check must not fail");

        // 4. Return the first `len` authenticated bits.
        Ok(authenticated_bits[0..len].to_vec())
    }

    /// Compute `len` authenticated bit shares.
    fn random_authenticated_shares(&mut self, len: usize) -> Result<Vec<AuthBit>, Error> {
        let len_unchecked = len + SEC_MARGIN_SHARE_AUTH;
        let authenticated_bits: Vec<AuthBit> = self.abit_pool.drain(..len_unchecked).collect();
        self.log(&format!(
            "Obtained {} authenticated bits from the pool to generate {len} authenticated bit shares.",
            authenticated_bits.len()
        ));

        // Malicious security checks
        for r in len..len + SEC_MARGIN_SHARE_AUTH {
            let domain_separator_0 = format!("Share authentication {} - 0", self.id);
            let domain_separator_1 = format!("Share authentication {} - 1", self.id);
            let domain_separator_macs = format!("Share authentication {} - macs", self.id);

            let mut mac_0 = [0u8; MAC_LENGTH]; // XOR of all auth keys
            for key in authenticated_bits[r].mac_keys.iter() {
                for byte in 0..mac_0.len() {
                    mac_0[byte] ^= key.mac_key[byte];
                }
            }

            let mut mac_1 = [0u8; MAC_LENGTH]; // XOR of all (auth keys xor Delta)
            for key in authenticated_bits[r].mac_keys.iter() {
                for byte in 0..mac_1.len() {
                    mac_1[byte] ^= key.mac_key[byte] ^ self.global_mac_key[byte];
                }
            }

            let all_macs: Vec<u8> = authenticated_bits[r].serialize_bit_macs(); // the authenticated bit and all macs on it

            let (com0, op0) =
                Commitment::new(&mac_0, domain_separator_0.as_bytes(), &mut self.entropy);
            let (com1, op1) =
                Commitment::new(&mac_1, domain_separator_1.as_bytes(), &mut self.entropy);
            let (com_macs, op_macs) = Commitment::new(
                &all_macs,
                domain_separator_macs.as_bytes(),
                &mut self.entropy,
            );

            let received_commitments = self.broadcast_commitments(com0, com1, com_macs)?;

            let received_mac_openings = self.broadcast_opening(op_macs)?;

            // open the other parties commitments to obtain their bit values and MACs
            let mut other_bits_macs = Vec::new();
            for (party, their_opening) in received_mac_openings {
                let (_, _, _, their_mac_commitment) = received_commitments
                    .iter()
                    .find(|(committing_party, _, _, _)| *committing_party == party)
                    .expect("should have received commitments from all parties");
                other_bits_macs.push((
                    party,
                    AuthBit::deserialize_bit_macs(&their_mac_commitment.open(&their_opening)?)?,
                ));
            }

            debug_assert_eq!(
                other_bits_macs.len(),
                self.num_parties - 1,
                "should have received valid openings from all other parties"
            );

            // compute xor of all opened MACs for each party
            let mut xor_macs = vec![[0u8; MAC_LENGTH]; self.num_parties];

            for (maccing_party, xored_mac) in xor_macs.iter_mut().enumerate() {
                if maccing_party == self.id {
                    // don't need to compute this for ourselves
                    continue;
                }

                for p in 0..self.num_parties {
                    let their_mac = if p == self.id {
                        authenticated_bits[r]
                            .macs
                            .iter()
                            .find(|(party, _mac)| *party == maccing_party)
                            .expect("should have MACs from all other parties")
                            .1
                    } else {
                        let (_sending_party, (_other_bit, other_macs)) = other_bits_macs
                            .iter()
                            .find(|(sending_party, _rest)| *sending_party == p)
                            .expect(
                                "should have gotten bit values and MACs from all other parties",
                            );
                        other_macs[maccing_party]
                    };
                    for byte in 0..MAC_LENGTH {
                        xored_mac[byte] ^= their_mac[byte];
                    }
                }
            }

            let mut b_i = false;
            // compute our own xor of all bits
            for (_party, (bit, _macs)) in other_bits_macs.iter() {
                b_i ^= *bit;
            }

            // compute the other parties xor-ed bits to know which openings they are sending
            let mut xor_bits = vec![authenticated_bits[r].bit.value; self.num_parties];
            for j in 0..self.num_parties {
                if j == self.id {
                    xor_bits[j] = b_i;
                }
                for (party, (bit, _macs)) in other_bits_macs.iter() {
                    if *party == j {
                        continue;
                    }
                    xor_bits[j] ^= bit;
                }
            }

            let received_bit_openings = if b_i {
                self.broadcast_opening(op1)?
            } else {
                self.broadcast_opening(op0)?
            };

            for (party, bit_opening) in received_bit_openings {
                let (_, their_com0, their_com1, _) = received_commitments
                    .iter()
                    .find(|(committing_party, _, _, _)| *committing_party == party)
                    .expect("should have received commitments from all other parties");
                let their_mac = if !xor_bits[party] {
                    their_com0.open(&bit_opening).unwrap()
                } else {
                    their_com1.open(&bit_opening).unwrap()
                };

                if their_mac != xor_macs[party] {
                    self.log(&format!(
                        "Error while checking party {}'s bit commitment!",
                        party
                    ));
                    return Err(Error::CheckFailed);
                }
            }

            self.log(&format!(
                "Completed share auth check [{}/{}]",
                r + 1 - len,
                SEC_MARGIN_SHARE_AUTH
            ));
        }

        Ok(authenticated_bits[0..len].to_vec())
    }

    /// Compute unauthenticated cross terms in an AND triple output share.
    fn half_and(&mut self, x: &AuthBit, y: &AuthBit) -> Result<bool, Error> {
        /// Obtain the least significant bit of some hash output
        fn lsb(input: &[u8]) -> bool {
            (input[input.len() - 1] & 1) != 0
        }

        let domain_separator = format!("half-and-hash-{}", self.id);

        let mut t_js = vec![false; self.num_parties];
        let mut s_js = vec![false; self.num_parties];

        // receive earlier hashes
        for _j in 0..self.id {
            let hashes_message = self.channels.listen.recv().unwrap();
            if let Message {
                from,
                to,
                payload: MessagePayload::HalfAndHashes(hash_j_0, hash_j_1),
            } = hashes_message
            {
                debug_assert_eq!(to, self.id);
                let their_mac = x
                    .macs
                    .iter()
                    .find(|(party, _mac)| *party == from)
                    .expect("should have MACs from all other parties")
                    .1;
                let hash_lsb = lsb(&hash_to_mac_width(domain_separator.as_bytes(), &their_mac));
                let t_j = if x.bit.value {
                    hash_j_1 ^ hash_lsb
                } else {
                    hash_j_0 ^ hash_lsb
                };
                t_js[from] = t_j;
            } else {
                return Err(Error::UnexpectedMessage(hashes_message));
            }
        }

        for j in 0..self.num_parties {
            if j == self.id {
                continue;
            }
            let s_j = self
                .entropy
                .bit()
                .expect("sufficient randomness should have been provided externally");
            s_js[j] = s_j;

            // K_i[x^j]
            let input_0 = x
                .mac_keys
                .iter()
                .find(|key| key.bit_holder == j)
                .expect("should have keys for all other parties")
                .mac_key;

            // K_i[x^j] xor Delta_i
            let mut input_1 = [0u8; MAC_LENGTH];
            for byte in 0..MAC_LENGTH {
                input_1[byte] = input_0[byte] ^ self.global_mac_key[byte];
            }

            let h_0 = lsb(&hash_to_mac_width(domain_separator.as_bytes(), &input_0)) ^ s_j;
            let h_1 =
                lsb(&hash_to_mac_width(domain_separator.as_bytes(), &input_1)) ^ s_j ^ y.bit.value;
            self.channels.parties[j]
                .send(Message {
                    from: self.id,
                    to: j,
                    payload: MessagePayload::HalfAndHashes(h_0, h_1),
                })
                .unwrap();
        }

        // receive later hashes
        for _j in self.id + 1..self.num_parties {
            let hashes_message = self.channels.listen.recv().unwrap();
            if let Message {
                from,
                to,
                payload: MessagePayload::HalfAndHashes(hash_j_0, hash_j_1),
            } = hashes_message
            {
                debug_assert_eq!(to, self.id);
                let their_mac = x
                    .macs
                    .iter()
                    .find(|(party, _mac)| *party == from)
                    .expect("should have MACs from all other parties")
                    .1;
                let hash_lsb = lsb(&hash_to_mac_width(domain_separator.as_bytes(), &their_mac));
                let t_j = if x.bit.value {
                    hash_j_1 ^ hash_lsb
                } else {
                    hash_j_0 ^ hash_lsb
                };
                t_js[from] = t_j;
            } else {
                return Err(Error::UnexpectedMessage(hashes_message));
            }
        }

        self.sync().expect("sync should always succeed");

        let mut v_i = false;
        for j in 0..self.num_parties {
            if j == self.id {
                continue;
            }
            v_i ^= t_js[j] ^ s_js[j];
        }

        Ok(v_i)
    }

    /// Compute authenticated AND triples.
    fn random_leaky_and(&mut self, len: usize) -> Result<Vec<(AuthBit, AuthBit, AuthBit)>, Error> {
        let mut results = Vec::new();
        let mut shares = self.random_authenticated_shares(3 * len)?;
        for _i in 0..len {
            let x = shares.pop().expect("requested enough authenticated bits");
            let y = shares.pop().expect("requested enough authenticated bits");
            let mut r = shares.pop().expect("requested enough authenticated bits");

            let v_i = self.half_and(&x, &y)?;

            let z_i_value = y.bit.value && x.bit.value ^ v_i;
            let e_i_value = z_i_value ^ r.bit.value;

            let other_e_is = self.broadcast(&[e_i_value as u8])?;
            for key in r.mac_keys.iter_mut() {
                let (_, other_e_j) = other_e_is
                    .iter()
                    .find(|(party, _)| *party == key.bit_holder)
                    .expect("should have received e_j from every other party j");
                let correction_necessary = other_e_j[0] != 0;
                if correction_necessary {
                    for byte in 0..MAC_LENGTH {
                        key.mac_key[byte] ^= self.global_mac_key[byte];
                    }
                }
            }
            let z = r;

            // Triple Check
            // 1. compute Phi
            let mut phi = [0u8; MAC_LENGTH];
            for key in y.mac_keys.iter() {
                let (_, their_mac) = y
                    .macs
                    .iter()
                    .find(|(maccing_party, _)| *maccing_party == key.bit_holder)
                    .unwrap();
                for byte in 0..MAC_LENGTH {
                    phi[byte] ^= key.mac_key[byte] ^ their_mac[byte];
                }
            }

            if y.bit.value {
                for byte in 0..MAC_LENGTH {
                    phi[byte] ^= self.global_mac_key[byte];
                }
            }

            // 2. receive earlier Us
            let mut mac_phis = Vec::new();
            let mut key_phis = Vec::new();

            for _j in 0..self.id {
                let u_message = self.channels.listen.recv().unwrap();
                if let Message {
                    from,
                    to,
                    payload: MessagePayload::LeakyAndU(u),
                } = u_message
                {
                    debug_assert_eq!(self.id, to);
                    // compute M_phi
                    let domain_separator_mac = &format!("mac-phi-{}-{}", self.id, from);
                    let (_, their_mac) = x
                        .macs
                        .iter()
                        .find(|(maccing_party, _)| *maccing_party == from)
                        .expect("should have MACs from all other parties");
                    let mut mac_phi = hash_to_mac_width(domain_separator_mac.as_bytes(), their_mac);
                    if x.bit.value {
                        for byte in 0..MAC_LENGTH {
                            mac_phi[byte] ^= u[byte];
                        }
                    }
                    mac_phis.push((from, mac_phi));
                } else {
                    return Err(Error::UnexpectedMessage(u_message));
                }
            }

            // 2. send out own Us
            for j in 0..self.num_parties {
                if j == self.id {
                    continue;
                }
                // compute k_phi
                let domain_separator_key = &format!("key-phi-{}-{}", self.id, j);
                let my_key = x
                    .mac_keys
                    .iter()
                    .find(|k| k.bit_holder == j)
                    .expect("should have keys for all other parties' bits");

                let k_phi = hash_to_mac_width(domain_separator_key.as_bytes(), &my_key.mac_key);
                key_phis.push((j, k_phi));

                // compute U_j
                let domain_separator_u = &format!("u-phi-{}-{}", self.id, j);
                let u_j_hash = hash_to_mac_width(
                    domain_separator_u.as_bytes(),
                    &xor_mac_width(&my_key.mac_key, &self.global_mac_key),
                );
                let u_j = xor_mac_width(&u_j_hash, &k_phi);
                let u_j = xor_mac_width(&u_j, &phi);

                self.channels.parties[j]
                    .send(Message {
                        from: self.id,
                        to: j,
                        payload: MessagePayload::LeakyAndU(u_j),
                    })
                    .unwrap();
            }

            // 2. Receive later Us
            for _j in self.id + 1..self.num_parties {
                let u_message = self.channels.listen.recv().unwrap();
                if let Message {
                    from,
                    to,
                    payload: MessagePayload::LeakyAndU(u),
                } = u_message
                {
                    debug_assert_eq!(self.id, to);
                    // compute M_phi
                    let domain_separator_mac = &format!("mac-phi-{}-{}", self.id, from);
                    let (_, their_mac) = x
                        .macs
                        .iter()
                        .find(|(maccing_party, _)| *maccing_party == from)
                        .expect("should have MACs from all other parties");
                    let mut mac_phi = hash_to_mac_width(domain_separator_mac.as_bytes(), their_mac);
                    if x.bit.value {
                        for byte in 0..MAC_LENGTH {
                            mac_phi[byte] ^= u[byte];
                        }
                    }
                    mac_phis.push((from, mac_phi));
                } else {
                    return Err(Error::UnexpectedMessage(u_message));
                }
            }

            self.sync().expect("sync should always succeed");

            // 3. Compute H_i
            let mut h = [0u8; MAC_LENGTH];

            for (j, key_phi) in key_phis {
                let (_, mac_phi) = mac_phis
                    .iter()
                    .find(|(maccing_party, _)| *maccing_party == j)
                    .expect("should have a MAC from every other party");
                let intermediate_xor = xor_mac_width(&key_phi, mac_phi);
                h = xor_mac_width(&h, &intermediate_xor);
            }

            for key in z.mac_keys.iter() {
                let (_, their_mac) = z
                    .macs
                    .iter()
                    .find(|(maccing_party, _)| key.bit_holder == *maccing_party)
                    .expect("should have MACs from all other parties");
                let intermediate_xor = xor_mac_width(&key.mac_key, their_mac);
                h = xor_mac_width(&h, &intermediate_xor);
            }

            if x.bit.value {
                h = xor_mac_width(&h, &phi);
            }
            if z.bit.value {
                h = xor_mac_width(&h, &self.global_mac_key);
            }

            // 4. Broadcast H_is
            let other_hs = self.broadcast(&h)?;

            // 5. Check H_is xor to 0
            let mut test = h;
            for (_, other_h) in other_hs {
                test = xor_mac_width(
                    &test,
                    &other_h
                        .try_into()
                        .expect("should have received the right number of bytes"),
                );
            }

            if test != [0u8; MAC_LENGTH] {
                return Err(Error::CheckFailed);
            }

            results.push((x, y, z));
        }

        Ok(results)
    }

    /// Perform the active_security check for bit authentication
    fn bit_auth_check(&mut self, auth_bits: &[AuthBit]) -> Result<(), Error> {
        for j in 0..SEC_MARGIN_BIT_AUTH {
            // a) Sample `ell'` random bit.s
            let r = self.coin_flip(auth_bits.len())?;

            // b) Compute x_j = XOR_{m in [ell']} r_m & x_m
            let mut x_j = false;
            for (m, xm) in auth_bits.iter().enumerate() {
                x_j ^= ith_bit(m, &r) & xm.bit.value;
            }

            // broadcast x_j
            let other_x_j_bytes = self.broadcast(&[x_j as u8])?;

            let mut other_x_js = Vec::new();
            for (party, other_x_j) in other_x_j_bytes {
                debug_assert!(other_x_j.len() == 1);
                other_x_js.push((party, other_x_j[0] != 0))
            }

            self.sync().expect("synchronization should have succeeded");

            // c) Compute xored keys for other parties
            let mut xored_keys = vec![[0u8; MAC_LENGTH]; self.num_parties];
            let mut xored_tags = vec![[0u8; MAC_LENGTH]; self.num_parties];
            for (m, xm) in auth_bits.iter().enumerate() {
                if ith_bit(m, &r) {
                    for mac_keys in xm.mac_keys.iter() {
                        for byte in 0..mac_keys.mac_key.len() {
                            xored_keys[mac_keys.bit_holder][byte] ^= mac_keys.mac_key[byte];
                        }
                    }
                    for (key_holder, tag) in xm.macs.iter() {
                        for (index, tag_byte) in tag.iter().enumerate() {
                            xored_tags[*key_holder][index] ^= *tag_byte;
                        }
                    }
                }
            }

            // d) Receive / Send xored MACs
            let mut received_macs = Vec::new();
            for _i in 0..self.id {
                let mac_message = self
                    .channels
                    .listen
                    .recv()
                    .expect("all parties should be online");
                if let MessagePayload::Mac(mac) = mac_message.payload {
                    debug_assert_eq!(mac_message.to, self.id, "Wrong recipient for MAC message");
                    received_macs.push((mac_message.from, mac));
                } else {
                    return Err(Error::UnexpectedMessage(mac_message));
                }
            }

            for i in 0..self.num_parties {
                if i == self.id {
                    continue;
                }

                let tag = xored_tags[i];

                let mac_message = Message {
                    from: self.id,
                    to: i,
                    payload: MessagePayload::Mac(tag),
                };
                self.channels.parties[i]
                    .send(mac_message)
                    .expect("all parties should be online");
            }

            for _i in self.id + 1..self.num_parties {
                let mac_message = self
                    .channels
                    .listen
                    .recv()
                    .expect("all parties should be online");
                if let MessagePayload::Mac(mac) = mac_message.payload {
                    debug_assert_eq!(mac_message.to, self.id, "Wrong recipient for MAC message");
                    received_macs.push((mac_message.from, mac));
                } else {
                    return Err(Error::UnexpectedMessage(mac_message));
                }
            }

            self.sync().expect("synchronization should have succeeded");

            // verify MACs
            for (party, mac) in received_macs {
                let other_xj = other_x_js
                    .iter()
                    .find(|(xj_party, _)| *xj_party == party)
                    .expect("should have an xj from every other party")
                    .1;
                let key = xored_keys[party];

                if !verify_mac(&other_xj, &mac, &key, &self.global_mac_key) {
                    panic!("Party {}: {}'s MAC verification failed: {other_xj}\nMAC: {mac:?}\nLocal key: {key:?}\nGlobal key: {:?}\n", self.id, party, self.global_mac_key);
                }
            }

            self.log(&format!(
                "Completed bit auth check [{}/{}]",
                j + 1,
                SEC_MARGIN_BIT_AUTH
            ));
        }
        Ok(())
    }

    /// Jointly sample a random byte string of length `len / 8 + 1`, i.e. enough
    /// to contain `len` random bits.
    fn coin_flip(&mut self, len: usize) -> Result<Vec<u8>, Error> {
        let my_contribution = self
            .entropy
            .bytes(len / 8 + 1)
            .expect("sufficient randomness should have been provided externally")
            .to_owned();
        let other_contributions = self.broadcast(&my_contribution)?;

        let mut result = my_contribution;
        for (_party, their_contribution) in other_contributions {
            debug_assert_eq!(
                their_contribution.len(),
                result.len(),
                "all randomness contributions must be of the same length"
            );
            for i in 0..result.len() {
                result[i] ^= their_contribution[i]
            }
        }

        Ok(result)
    }

    /// Initiate an OT session as the Sender.
    ///
    /// The sender needs to provide two inputs to the OT protocol and receives
    /// no output.
    fn ot_send(
        &mut self,
        receiver_address: Sender<SubMessage>,
        my_inbox: Receiver<SubMessage>,
        receiver_id: usize,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<(), Error> {
        let domain_separator = format!("OT-{}-{}", self.id, receiver_id);
        let (sender_state, sender_commitment) =
            crate::primitives::ot::OTSender::init(&mut self.entropy, domain_separator.as_bytes())?;
        receiver_address
            .send(SubMessage::OTCommit(sender_commitment))
            .expect("all parties should be online");

        let selection_msg = my_inbox.recv().expect("all parties should be online");
        if let SubMessage::OTSelect(selection) = selection_msg {
            let payload =
                sender_state.send(left_input, right_input, &selection, &mut self.entropy)?;

            receiver_address
                .send(SubMessage::OTSend(payload))
                .expect("all parties should be online");
            Ok(())
        } else {
            Err(Error::UnexpectedSubprotocolMessage(selection_msg))
        }
    }

    /// Listen for an OT initiation as the receiver.
    ///
    /// The receiver needs to provide a choice of left or right sender input to
    /// the protocol and receives the chosen sender input.
    fn ot_receive(
        &mut self,
        choose_left_input: bool,
        sender_address: Sender<SubMessage>,
        my_inbox: Receiver<SubMessage>,
        sender_id: usize,
    ) -> Result<Vec<u8>, Error> {
        let ot_commit_msg = my_inbox.recv().expect("all parties should be online");
        if let SubMessage::OTCommit(commitment) = ot_commit_msg {
            let domain_separator = format!("OT-{}-{}", sender_id, self.id);
            let (receiver_state, receiver_selection) = crate::primitives::ot::OTReceiver::select(
                &mut self.entropy,
                domain_separator.as_bytes(),
                commitment,
                choose_left_input,
            )?;
            sender_address
                .send(SubMessage::OTSelect(receiver_selection))
                .expect("all parties should be online");
            let payload_msg = my_inbox.recv().expect("all parties should be online");
            if let SubMessage::OTSend(payload) = payload_msg {
                let result = receiver_state.receive(payload)?;
                Ok(result)
            } else {
                Err(Error::UnexpectedSubprotocolMessage(payload_msg))
            }
        } else {
            Err(Error::UnexpectedSubprotocolMessage(ot_commit_msg))
        }
    }

    /// Initiate an equality check with another party.
    ///
    /// The initiator has to provide its own input value to the check and will
    /// learn whether that value is the same as the responders.
    fn eq_initiate(&mut self, i: usize, my_value: &[u8]) -> Result<bool, Error> {
        let (own_sender, own_receiver) = mpsc::channel::<SubMessage>();
        let (their_sender, their_receiver) = mpsc::channel::<SubMessage>();

        let channel_msg = Message {
            from: self.id,
            to: i,
            payload: MessagePayload::SubChannel(own_sender, their_receiver),
        };
        self.channels.parties[i]
            .send(channel_msg)
            .expect("all parties should be online");

        let dst = format!("EQ-{}-{}", self.id, i);
        let (commitment, opening) = Commitment::new(my_value, dst.as_bytes(), &mut self.entropy);
        their_sender
            .send(SubMessage::EQCommit(commitment))
            .expect("all parties should be online");

        let responder_message = own_receiver.recv().expect("all parties should be online");
        if let SubMessage::EQResponse(their_value) = responder_message {
            let res = their_value == my_value;
            their_sender
                .send(SubMessage::EQOpening(opening))
                .expect("all parties should be online");
            Ok(res)
        } else {
            Err(Error::UnexpectedSubprotocolMessage(responder_message))
        }
    }

    /// Listen for an equality check initiation.
    ///
    /// The responder has to provide its own input value to the check and will
    /// learn whether that value is the same as the initators.
    fn eq_respond(&mut self, my_value: &[u8]) -> Result<bool, Error> {
        let channel_msg = self
            .channels
            .listen
            .recv()
            .expect("all parties should be online");

        if let Message {
            to,
            from: _from,
            payload: MessagePayload::SubChannel(their_channel, my_channel),
        } = channel_msg
        {
            debug_assert_eq!(to, self.id);
            let commit_message = my_channel.recv().expect("all parties should be online");
            if let SubMessage::EQCommit(commitment) = commit_message {
                their_channel
                    .send(SubMessage::EQResponse(my_value.to_vec()))
                    .expect("all parties should be online");
                let opening_message = my_channel.recv().expect("all parties should be online");
                if let SubMessage::EQOpening(opening) = opening_message {
                    let their_value = commitment.open(&opening)?;
                    Ok(my_value == their_value)
                } else {
                    Err(Error::UnexpectedSubprotocolMessage(opening_message))
                }
            } else {
                Err(Error::UnexpectedSubprotocolMessage(commit_message))
            }
        } else {
            Err(Error::UnexpectedMessage(channel_msg))
        }
    }

    /// Generate a fresh bit id, increasing the internal bit counter.
    fn fresh_bit_id(&mut self) -> BitID {
        let res = self.bit_counter;
        self.bit_counter += 1;
        BitID(res)
    }

    /// Initiate a two-party bit authentication session to oblivious obtain a
    /// MAC from the authenticator on a locally held bit.
    ///
    /// The authenticator computes `left_value = K + Delta` and `right_value =
    /// K` where `K` is a fresh mac key and `Delta` is the authenticator's
    /// global MAC key. If `b` is the bit holders local bit, the bit holder can
    /// thus obliviously obtain a MAC `M = K + b * Delta` by setting `b` as
    /// their choice bit as an OT receiver with the authenticator acting as OT
    /// sender with inputs `left_value` and `right value`.
    fn obtain_bit_authentication(
        &mut self,
        authenticator: usize,
        local_bit: &Bit,
    ) -> Result<Mac, Error> {
        // Set up channels for an OT subprotocol session with the authenticator.
        let (my_address, my_inbox) = mpsc::channel::<SubMessage>();
        let (their_address, their_inbox) = mpsc::channel::<SubMessage>();

        // The authenticator has to initiate an OT session, so request a bit
        // authentication session using the generated channels.
        self.channels.parties[authenticator]
            .send(Message {
                from: self.id,
                to: authenticator,
                payload: MessagePayload::RequestBitAuth(
                    local_bit.id.clone(),
                    my_address,
                    their_inbox,
                ),
            })
            .expect("all parties should be online");

        // Join the authenticator's OT session with the local bit value as the
        // receiver choice input.
        let received_mac: Mac = self
            .ot_receive(local_bit.value, their_address, my_inbox, authenticator)?
            .try_into()
            .expect("should receive a MAC of the right length");

        Ok(received_mac)
    }

    /// Listen for a two-party bit authentication request to oblivious
    /// authenticate a bit holders local bit and obtain the corresponding MAC
    /// key.
    ///
    /// The authenticator computes `left_value = K + Delta` and `right_value =
    /// K` where `K` is a fresh mac key and `Delta` is the authenticator's
    /// global MAC key. If `b` is the bit holders local bit, the bit holder can
    /// thus obliviously obtain a MAC `M = K + b * Delta` by setting `b` as
    /// their choice bit as an OT receiver with the authenticator acting as OT
    /// sender with inputs `left_value` and `right value`.
    fn provide_bit_authentication(&mut self, bit_holder: usize) -> Result<BitKey, Error> {
        let request_msg = self
            .channels
            .listen
            .recv()
            .expect("all parties should be online");

        if let Message {
            to,
            from,
            payload: MessagePayload::RequestBitAuth(holder_bit_id, their_address, my_inbox),
        } = request_msg
        {
            debug_assert_eq!(to, self.id, "Got a wrongly addressed message");

            // Compute the MACs for both possible values of the bit holder's
            // bit. Note that `mac_on_false` is simply the fresh local mac_key.
            let (mac_on_true, mac_on_false) = mac(&true, &self.global_mac_key, &mut self.entropy);

            // Initiate an OT session with the bit holder giving the two MACs as
            // sender inputs.
            self.ot_send(their_address, my_inbox, from, &mac_on_true, &mac_on_false)?;

            Ok(BitKey {
                holder_bit_id,
                bit_holder,
                mac_key: mac_on_false,
            })
        } else {
            self.log(&format!("Bit Auth: Unexpected message {request_msg:?}"));
            Err(Error::UnexpectedMessage(request_msg))
        }
    }

    /// Run the function independent pre-processing phase of the protocol.
    pub fn function_independent(&mut self) {
        todo!("the function-independent pre-processing phase is not yet implemented (cf. GitHub issue #51")
    }

    /// Run the function-dependent pre-processing phase of the protocol.
    pub fn function_dependent(&mut self) {
        todo!("the function-dependent pre-processing phase is not yet implemented (cf. GitHub issue #51")
    }

    /// Run the input-processing phase of the protocol.
    pub fn input_processing(&mut self) {
        todo!("the input processing phase is not yet implemented (cf. GitHub issue #52")
    }

    /// Run the circuit evaluation phase of the protocol.
    pub fn evaluate_circuit(&mut self) {
        todo!("the circuit evaluation phase is not yet implemented (cf. GitHub issue #54")
    }

    /// Run the output processing phase of the protocol
    pub fn output_processing(&mut self) {
        todo!("the output processing phase is not yet implemented (cf. GitHub issue #53")
    }

    /// Run the MPC protocol, returning the parties output, if any.
    pub fn run(&mut self, precompute: Option<usize>) -> Result<Option<Vec<bool>>, Error> {
        use std::io::Write;
        if let Some(target_number) = precompute {
            self.log(&format!(
                "Pre-computing {target_number} bit authentication(s)..."
            ));

            // We want to compute 1 authenticated share, so need `1 + SEC_MARGIN_SHARE_AUTH` bits in the pool.
            self.abit_pool = self.precompute_abits(target_number)?;

            let file = std::fs::File::create(format!("{}.triples", self.id))
                .map_err(|_| Error::OtherError)?;
            let mut writer = std::io::BufWriter::new(file);
            serde_json::to_writer(&mut writer, &(self.global_mac_key, &self.abit_pool))
                .map_err(|_| Error::OtherError)?;
            writer.flush().unwrap();
            Ok(None)
        } else {
            let num_auth_shares = 1;
            self.log(&format!(
                "Want to generate {num_auth_shares} authenticated share(s)"
            ));
            self.log("Trying to read authenticated bits from file");
            let file = std::fs::File::open(format!("{}.triples", self.id));
            if let Ok(f) = file {
                (self.global_mac_key, self.abit_pool) =
                    serde_json::from_reader(f).map_err(|_| Error::OtherError)?;
                self.log(&format!(
                    "Read {} authenticated bits from pool",
                    self.abit_pool.len()
                ));

                let max_id = self
                    .abit_pool
                    .iter()
                    .max_by_key(|abit| abit.bit.id.0)
                    .map(|abit| abit.bit.id.0)
                    .unwrap_or(0);
                self.bit_counter = max_id;

                if num_auth_shares + SEC_MARGIN_SHARE_AUTH > self.abit_pool.len() {
                    self.log(&format!(
                        "Insufficient precomputation (by {})",
                        num_auth_shares + SEC_MARGIN_SHARE_AUTH - self.abit_pool.len()
                    ));
                    return Ok(None);
                }
            } else {
                self.log("Could not read pre-computed bit authentications from file.");
            }

            self.log("Starting share authentication");
            let _shares = self.random_authenticated_shares(num_auth_shares)?;

            //let bucket_size = (STATISTICAL_SECURITY as u32 / self.circuit.num_gates().ilog2()) as usize;
            // let bucket_size = 3;
            // self.log("Computing AND triples");
            //let _and_shares = self.random_and_shares(2, bucket_size)?;
            Ok(None)
        }
    }

    /// Synchronise parties.
    ///
    /// In all other communication rounds, parties send in increasing order of
    /// their numeric identifiers. In order to prevent early parties from
    /// advancing to the next phase of the procotol before later parties have
    /// caught up, this synchronization mechanism reverses the turn order,
    /// making numerically smaller ID parties first wait for the synchronisation
    /// signal from numerically larger ID parties.
    ///
    /// For this to work as a synchronisation mechanism it is crucial that
    /// synchronisation is the only communication round with decreasing turn
    /// order.
    fn sync(&self) -> Result<(), Error> {
        for _i in (self.id + 1..self.num_parties).rev() {
            let sync_msg = self
                .channels
                .listen
                .recv()
                .expect("all parties should be online");
            if let MessagePayload::Sync = sync_msg.payload {
                continue;
            } else {
                return Err(Error::UnexpectedMessage(sync_msg));
            }
        }

        for i in (0..self.num_parties).rev() {
            if i == self.id {
                continue;
            }
            self.channels.parties[i]
                .send(Message {
                    from: self.id,
                    to: i,
                    payload: MessagePayload::Sync,
                })
                .expect("all parties should be online");
        }

        for _ in (0..self.id).rev() {
            let sync_msg = self
                .channels
                .listen
                .recv()
                .expect("all parties should be online");
            if let MessagePayload::Sync = sync_msg.payload {
                continue;
            } else {
                return Err(Error::UnexpectedMessage(sync_msg));
            }
        }

        Ok(())
    }

    /// Utility function to provide debug output during the protocol run.
    fn log(&mut self, message: &str) {
        if self.enable_logging {
            eprintln!("[Party {} @ {}]: {}", self.id, self.log_counter, message);
            self.log_counter += 1;
        }
    }
}
