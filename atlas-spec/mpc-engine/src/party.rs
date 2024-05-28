//! This module defines the behaviour of protocol parties in the different
//! phases of the protocol.

use hacspec_lib::Randomness;
use hmac::{hkdf_expand, hkdf_extract};

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
    Error, COMPUTATIONAL_SECURITY, STATISTICAL_SECURITY,
};

use std::sync::mpsc::{self, Receiver, Sender};

/// Additional bit authentications computed for malicious security checks.
const SEC_MARGIN_BIT_AUTH: usize = 2 * STATISTICAL_SECURITY * 8;
/// Additional cost of authenticating a number of bits into authenticated shares.
pub(crate) const SEC_MARGIN_SHARE_AUTH: usize = STATISTICAL_SECURITY * 8;

const EVALUATOR_ID: usize = 0;
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

/// A Wire label given by a party.
#[derive(Debug, Clone)]
pub struct WireLabel([u8; COMPUTATIONAL_SECURITY]);

struct GarbledAnd {
    sender: usize,
    gate_index: usize,
    g0: Vec<u8>,
    g1: Vec<u8>,
    g2: Vec<u8>,
    g3: Vec<u8>,
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
    /// The party's input to the circuit
    input_values: Vec<bool>,
    /// A local source of random bits and bytes
    entropy: Randomness,
    /// Pool of pre-computed authenticated bits
    abit_pool: Vec<AuthBit>,
    /// Pool of pre-computed authenticated shares
    ashare_pool: Vec<AuthBit>,
    /// Tracks the current phase of protocol execution
    current_phase: ProtocolPhase,
    /// Whether to log events
    enable_logging: bool,
    /// Incremental counter for ordering logs
    log_counter: u128,
    /// Wire labels for every wire in the circuit
    wire_shares: Vec<Option<(AuthBit, Option<WireLabel>)>>,
    /// The evaluators list of received garbled AND gates (from, gate_index, g0, g1, g2, g3)
    garbled_ands: Option<Vec<(usize, usize, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)>>,
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
        input: &[bool],
        logging: bool,
        mut entropy: Randomness,
    ) -> Self {
        // Validate the circuit
        circuit
            .validate_circuit_specification()
            .map_err(Error::Circuit)
            .unwrap();

        if circuit.input_widths[channels.id] != input.len() {
            panic!("Invalid input provided to party {}", channels.id)
        }

        Self {
            bit_counter: 0,
            id: channels.id,
            num_parties: channels.parties.len(),
            channels,
            global_mac_key: generate_mac_key(&mut entropy),
            circuit: circuit.clone(),
            entropy,
            abit_pool: Vec::new(),
            ashare_pool: Vec::new(),
            current_phase: ProtocolPhase::PreInit,
            log_counter: 0,
            input_values: input.to_owned(),
            enable_logging: logging,
            wire_shares: vec![None; circuit.num_gates()],
            garbled_ands: None,
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
        self.id == EVALUATOR_ID
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

    /// Transform authenticated bits into `len` authenticated bit shares.
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
                    return Err(Error::CheckFailed(
                        "Share Authentication failed".to_string(),
                    ));
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

        let domain_separator = b"half-and-hash";

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
                let hash_lsb = lsb(&hash_to_mac_width(domain_separator, &their_mac));
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

            let h_0 = lsb(&hash_to_mac_width(domain_separator, &input_0)) ^ s_j;
            let h_1 = lsb(&hash_to_mac_width(domain_separator, &input_1)) ^ s_j ^ y.bit.value;
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
                let hash_lsb = lsb(&hash_to_mac_width(domain_separator, &their_mac));
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
        let mut shares: Vec<AuthBit> = self.ashare_pool.drain(..3 * len).collect();
        for _i in 0..len {
            let x = shares.pop().expect("requested enough authenticated bits");
            let y = shares.pop().expect("requested enough authenticated bits");
            let mut r = shares.pop().expect("requested enough authenticated bits");

            let v_i = self.half_and(&x, &y)?;

            let z_i_value = (y.bit.value && x.bit.value) ^ v_i;
            let e_i_value = z_i_value ^ r.bit.value;

            let other_e_is = self.broadcast(&[e_i_value as u8])?;
            for key in r.mac_keys.iter_mut() {
                let (_, other_e_j) = other_e_is
                    .iter()
                    .find(|(party, _)| *party == key.bit_holder)
                    .expect("should have received e_j from every other party j");
                let correction_necessary = other_e_j[0] != 0;
                if correction_necessary {
                    key.mac_key = xor_mac_width(&key.mac_key, &self.global_mac_key);
                }
            }
            r.bit.value = z_i_value;
            let z = r;

            self.sync().expect("sync should always succeed");

            // Triple Check
            // 4. compute Phi
            let mut phi = [0u8; MAC_LENGTH];
            for key in y.mac_keys.iter() {
                let (_, their_mac) = y
                    .macs
                    .iter()
                    .find(|(maccing_party, _)| *maccing_party == key.bit_holder)
                    .unwrap();
                let intermediate_xor = xor_mac_width(&key.mac_key, their_mac);
                phi = xor_mac_width(&phi, &intermediate_xor);
            }

            if y.bit.value {
                phi = xor_mac_width(&phi, &self.global_mac_key);
            }

            // 5. receive earlier Us
            let mut mac_phis = Vec::new();
            let mut key_phis = Vec::new();
            let domain_separator_triple = b"triple-check";
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
                    let (_, their_mac) = x
                        .macs
                        .iter()
                        .find(|(maccing_party, _)| *maccing_party == from)
                        .expect("should have MACs from all other parties");
                    let mut mac_phi = hash_to_mac_width(domain_separator_triple, their_mac);
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

            // 5. send out own Us
            for j in 0..self.num_parties {
                if j == self.id {
                    continue;
                }
                // compute k_phi
                let my_key = x
                    .mac_keys
                    .iter()
                    .find(|k| k.bit_holder == j)
                    .expect("should have keys for all other parties' bits");

                let k_phi = hash_to_mac_width(domain_separator_triple, &my_key.mac_key);
                key_phis.push((j, k_phi));

                // compute U_j
                let u_j_hash = hash_to_mac_width(
                    domain_separator_triple,
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

            // 5. Receive later Us
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
                    let (_, their_mac) = x
                        .macs
                        .iter()
                        .find(|(maccing_party, _)| *maccing_party == from)
                        .expect("should have MACs from all other parties");
                    let mut mac_phi = hash_to_mac_width(domain_separator_triple, their_mac);
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

            // 6. Compute H_i
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

            // 6. Broadcast H_is
            let other_hs = self.broadcast(&h)?;

            // 7. Check H_is xor to 0
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
                return Err(Error::CheckFailed("Leaky AND xor check failed".to_string()));
            }

            results.push((x, y, z));
        }

        Ok(results)
    }

    /// Verifiably open an authenticated bit, revealing its value to all parties.
    fn open_bit(&mut self, bit: &AuthBit) -> Result<bool, Error> {
        let mut other_bits = Vec::new();

        // receive earlier parties MACs and verify them
        for _j in 0..self.id {
            let reveal_message = self.channels.listen.recv().unwrap();
            if let Message {
                from,
                to,
                payload: MessagePayload::BitReveal(value, mac),
            } = reveal_message
            {
                debug_assert_eq!(self.id, to);
                let my_key = bit
                    .mac_keys
                    .iter()
                    .find(|k| k.bit_holder == from)
                    .expect("should have a key for every other party");
                if !verify_mac(&value, &mac, &my_key.mac_key, &self.global_mac_key) {
                    return Err(Error::CheckFailed("Bit reveal failed".to_string()));
                }
                other_bits.push((from, value));
            } else {
                return Err(Error::UnexpectedMessage(reveal_message));
            }
        }

        // send out own MACs
        for j in 0..self.num_parties {
            if j == self.id {
                continue;
            }
            let (_, their_mac) = bit
                .macs
                .iter()
                .find(|(maccing_party, _mac)| j == *maccing_party)
                .expect("should have MACs from all other parties");
            self.channels.parties[j]
                .send(Message {
                    from: self.id,
                    to: j,
                    payload: MessagePayload::BitReveal(bit.bit.value, *their_mac),
                })
                .unwrap();
        }

        // receive later parties MACs and verify them
        for _j in self.id + 1..self.num_parties {
            let reveal_message = self.channels.listen.recv().unwrap();
            if let Message {
                from,
                to,
                payload: MessagePayload::BitReveal(value, mac),
            } = reveal_message
            {
                debug_assert_eq!(self.id, to);
                let my_key = bit
                    .mac_keys
                    .iter()
                    .find(|k| k.bit_holder == from)
                    .expect("should have a key for every other party");
                if !verify_mac(&value, &mac, &my_key.mac_key, &self.global_mac_key) {
                    return Err(Error::CheckFailed("Bit reveal failed".to_string()));
                }
                other_bits.push((from, value));
            } else {
                return Err(Error::UnexpectedMessage(reveal_message));
            }
        }

        let mut result = bit.bit.value;
        for (_, other_bit) in other_bits {
            result ^= other_bit
        }

        self.sync().expect("sync should always succeed");

        Ok(result)
    }

    /// Locally compute the XOR of two authenticated bits, which will itself be
    /// authenticated already.
    fn xor_abits(&mut self, a: &AuthBit, b: &AuthBit) -> AuthBit {
        let mut macs = Vec::new();
        for (maccing_party, mac) in a.macs.iter() {
            let mut xored_mac = [0u8; MAC_LENGTH];
            let other_mac = b
                .macs
                .iter()
                .find(|(party, _)| *party == *maccing_party)
                .expect("should have MACs from all other parties")
                .1;
            for byte in 0..MAC_LENGTH {
                xored_mac[byte] = mac[byte] ^ other_mac[byte];
            }
            macs.push((*maccing_party, xored_mac))
        }

        let mut mac_keys = Vec::new();
        for key in a.mac_keys.iter() {
            let mut xored_key = [0u8; MAC_LENGTH];
            let other_key = b
                .mac_keys
                .iter()
                .find(|other_key| key.bit_holder == other_key.bit_holder)
                .expect("should have two MAC keys for every other party")
                .mac_key;
            for byte in 0..MAC_LENGTH {
                xored_key[byte] = key.mac_key[byte] ^ other_key[byte];
            }
            mac_keys.push(BitKey {
                holder_bit_id: BitID(0), // XXX: We can't know their bit ID here, is it necessary for anything though?
                bit_holder: key.bit_holder,
                mac_key: xored_key,
            })
        }

        AuthBit {
            bit: Bit {
                id: self.fresh_bit_id(),
                value: a.bit.value ^ b.bit.value,
            },
            macs,
            mac_keys,
        }
    }

    fn and_abits(
        &mut self,
        random_triple: (AuthBit, AuthBit, AuthBit),
        x: &AuthBit,
        y: &AuthBit,
    ) -> Result<AuthBit, Error> {
        let (a, b, c) = random_triple;
        let blinded_x_share = self.xor_abits(x, &a);
        let blinded_y_share = self.xor_abits(y, &b);

        let blinded_x = self.open_bit(&blinded_x_share)?;
        let blinded_y = self.open_bit(&blinded_y_share)?;

        let mut result = c;
        if blinded_x {
            result = self.xor_abits(&result, &y);
        }
        if !blinded_y {
            result = self.xor_abits(&result, &a);
        }

        Ok(result)
    }

    /// Invert an authenticated bit, resulting in an authentication of the
    /// inverted bit.
    fn invert_abit(&mut self, a: &AuthBit) -> AuthBit {
        let mut mac_keys = a.mac_keys.clone();
        for key in mac_keys.iter_mut() {
            key.mac_key = xor_mac_width(&key.mac_key, &self.global_mac_key)
        }

        AuthBit {
            bit: Bit {
                id: self.fresh_bit_id(),
                value: a.bit.value ^ true,
            },
            macs: a.macs.clone(),
            mac_keys,
        }
    }

    fn check_and(&mut self, triple: &(AuthBit, AuthBit, AuthBit)) -> Result<(), Error> {
        let x = self.open_bit(&triple.0)?;
        let y = self.open_bit(&triple.1)?;
        let z = self.open_bit(&triple.2)?;

        if (x & y) != z {
            return Err(Error::CheckFailed("Invalid AND triple".to_owned()));
        }

        Ok(())
    }
    /// Build oblivious AND triples by combining leaky AND triples.
    fn random_and_shares(&mut self, len: usize) -> Result<Vec<(AuthBit, AuthBit, AuthBit)>, Error> {
        // get `len * BUCKET_SIZE` leaky ANDs
        let leaky_ands = self.random_leaky_and(len * self.circuit.and_bucket_size())?;

        // Shuffle the list.
        // Using random u128 bit indices for shuffling should prevent collisions
        // for at least 2^40 triples except with probability 2^-40.
        let random_indices = self.coin_flip(leaky_ands.len() * 8 * 16)?;
        let mut indexed_ands: Vec<(u128, (AuthBit, AuthBit, AuthBit))> = random_indices
            .chunks_exact(16)
            .map(|chunk| {
                u128::from_be_bytes(chunk.try_into().expect("chunks are exactly the right size"))
            })
            .zip(leaky_ands)
            .collect();
        indexed_ands.sort_by_key(|(index, _)| *index);
        let leaky_ands: Vec<&(AuthBit, AuthBit, AuthBit)> =
            indexed_ands.iter().map(|(_, triple)| triple).collect();

        // combine all buckets to single ANDs
        let mut results = Vec::new();
        for bucket in leaky_ands.chunks_exact(self.circuit.and_bucket_size()) {
            let (mut x, y, mut z) = bucket[0].clone();

            for (next_x, next_y, next_z) in bucket[1..].iter() {
                let d_i = self.xor_abits(&y, next_y);
                let d = self.open_bit(&d_i)?;

                x = self.xor_abits(&x, next_x);
                z = self.xor_abits(&z, next_z);
                if d {
                    z = self.xor_abits(&z, next_x);
                }
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
    ///
    /// This generates labeled wire shares for all input wires and AND-gate output wires.
    fn function_independent(&mut self) -> Result<(), Error> {
        self.ashare_pool =
            self.random_authenticated_shares(self.circuit.share_authentication_cost())?;

        for (gate_index, gate) in self.circuit.gates.iter().enumerate() {
            match *gate {
                crate::circuit::WiredGate::Input(_) | crate::circuit::WiredGate::And(_, _) => {
                    let share = self
                        .ashare_pool
                        .pop()
                        .expect("should have pre-computed enough authenticated random shares");
                    let label = self
                        .entropy
                        .bytes(COMPUTATIONAL_SECURITY)
                        .expect("should have provided enough randoness externally")
                        .try_into()
                        .expect("should have received the right number of bytes");
                    self.wire_shares[gate_index] = Some((share, Some(WireLabel(label))));
                }
                _ => continue,
            }
        }

        Ok(())
    }

    /// Run the function-dependent pre-processing phase of the protocol.
    fn function_dependent(&mut self) -> Result<Vec<GarbledAnd>, Error> {
        let num_and_triples = self.circuit.num_and_gates();
        self.log(&format!("Computing {} random AND triples", num_and_triples));
        let mut and_shares = self.random_and_shares(num_and_triples).unwrap();

        let mut garbled_ands = Vec::new();
        for (gate_index, gate) in self.circuit.clone().gates.iter().enumerate() {
            match *gate {
                crate::circuit::WiredGate::Xor(left, right) => {
                    let share_left = self.wire_shares[left]
                        .clone()
                        .expect("should have shares for all earlier wires already");
                    let share_right = self.wire_shares[right]
                        .clone()
                        .expect("should have shares for all earlier wires already");

                    let xor_share = self.xor_abits(&share_left.0, &share_right.0);
                    if self.is_evaluator() {
                        self.wire_shares[gate_index] = Some((xor_share, None));
                    } else {
                        let WireLabel(left_label) = share_left
                            .1
                            .expect("should have labels for all earlier shares already");
                        let WireLabel(right_label) = share_right
                            .1
                            .expect("should have labels for all earlier shares already");
                        let xor_label = xor_mac_width(&left_label, &right_label);
                        self.wire_shares[gate_index] =
                            Some((xor_share, Some(WireLabel(xor_label))));
                    }
                }
                crate::circuit::WiredGate::And(left, right) => {
                    let share_left = self.wire_shares[left]
                        .clone()
                        .expect("should have shares for all earlier wires already");
                    let share_right = self.wire_shares[right]
                        .clone()
                        .expect("should have shares for all earlier wires already");

                    let random_and_triple = and_shares
                        .pop()
                        .expect("should have pre-computed enough AND triples");
                    let and_share =
                        self.and_abits(random_and_triple, &share_left.0, &share_right.0)?;

                    let and_output_share = self.wire_shares[gate_index]
                        .clone()
                        .expect("should have labels for all AND gate output wires");

                    let and_0 = self.xor_abits(&and_output_share.0, &and_share);
                    let and_1 = self.xor_abits(&and_0, &share_left.0);
                    let and_2 = self.xor_abits(&and_0, &share_right.0);
                    let mut and_3 = self.xor_abits(&and_1, &share_right.0);

                    if self.is_evaluator() {
                        // do local computation and receive values
                        and_3.bit.value ^= true;

                        for _j in 1..self.num_parties {
                            let garbled_and_message = self.channels.listen.recv().unwrap();
                            if let Message {
                                from,
                                to,
                                payload: MessagePayload::GarbledAnd(g0, g1, g2, g3),
                            } = garbled_and_message
                            {
                                debug_assert_eq!(to, self.id);
                                garbled_ands.push(GarbledAnd {
                                    sender: from,
                                    gate_index,
                                    g0,
                                    g1,
                                    g2,
                                    g3,
                                });
                            } else {
                                return Err(Error::UnexpectedMessage(garbled_and_message));
                            }
                        }

                        for j in (1..self.num_parties).rev() {
                            self.channels.parties[j]
                                .send(Message {
                                    from: self.id,
                                    to: j,
                                    payload: MessagePayload::Sync,
                                })
                                .unwrap();
                        }
                    } else {
                        // do local computation and send values
                        let evaluator_key = and_3
                            .mac_keys
                            .iter_mut()
                            .find(|key| key.bit_holder == EVALUATOR_ID)
                            .expect("should have key for evaluator");
                        evaluator_key.mac_key =
                            xor_mac_width(&evaluator_key.mac_key, &self.global_mac_key);

                        let WireLabel(left_label) = share_left
                            .1
                            .expect("should have labels for all earlier wires");
                        let WireLabel(right_label) = share_right
                            .1
                            .expect("should have labels for all earlier wires");
                        let left_inv_label = xor_mac_width(&left_label, &self.global_mac_key);
                        let right_inv_label = xor_mac_width(&right_label, &self.global_mac_key);

                        let WireLabel(output_label) = and_output_share.1.unwrap();
                        let garble_0 = self.garble_and(
                            gate_index,
                            0,
                            and_0,
                            output_label,
                            left_label,
                            right_label,
                        );
                        let garble_1 = self.garble_and(
                            gate_index,
                            1,
                            and_1,
                            output_label,
                            left_label,
                            right_inv_label,
                        );
                        let garble_2 = self.garble_and(
                            gate_index,
                            2,
                            and_2,
                            output_label,
                            left_inv_label,
                            right_label,
                        );
                        let garble_3 = self.garble_and(
                            gate_index,
                            3,
                            and_3,
                            output_label,
                            left_inv_label,
                            right_inv_label,
                        );

                        self.channels
                            .evaluator
                            .send(Message {
                                from: self.id,
                                to: EVALUATOR_ID,
                                payload: MessagePayload::GarbledAnd(
                                    garble_0, garble_1, garble_2, garble_3,
                                ),
                            })
                            .unwrap();

                        let sync = self.channels.listen.recv().unwrap();
                        match sync.payload {
                            MessagePayload::Sync => {
                                if sync.from != EVALUATOR_ID || sync.to != self.id {
                                    return Err(Error::UnexpectedMessage(sync));
                                }
                            }
                            _ => return Err(Error::UnexpectedMessage(sync)),
                        }
                    }
                }
                crate::circuit::WiredGate::Not(input) => {
                    let share_input = self.wire_shares[input]
                        .clone()
                        .expect("should have shares for all earlier wires already");

                    let inverted_share = self.invert_abit(&share_input.0);
                    if self.is_evaluator() {
                        self.wire_shares[gate_index] = Some((inverted_share, None));
                    } else {
                        let WireLabel(input_label) = share_input
                            .1
                            .expect("should have labels for all earlier shares already");

                        let inverted_label = xor_mac_width(&input_label, &self.global_mac_key);
                        self.wire_shares[gate_index] =
                            Some((inverted_share, Some(WireLabel(inverted_label))));
                    }
                }
                crate::circuit::WiredGate::Input(_) => continue,
            }
        }

        Ok(garbled_ands)
    }

    /// Run the input-processing phase of the protocol.
    pub fn input_processing(
        &mut self,
    ) -> Result<(Vec<(usize, bool)>, Vec<(usize, usize, [u8; 16])>), Error> {
        let mut masked_wire_values = Vec::new();
        let mut wire_labels = Vec::new();
        let mut input_wire_offset = 0;
        for (party, input_width) in self.circuit.clone().input_widths.iter().enumerate() {
            for input_index in 0..*input_width {
                let input_wire_index = input_wire_offset + input_index;
                let wire_share = &self.wire_shares[input_wire_index]
                    .clone()
                    .expect("should have wire shares for all input wires");
                let mut masked_wire_value = false;
                if party == self.id {
                    let input_value = self.input_values[input_index];
                    // receive input wire shares from the other parties
                    let mut other_wire_mask_shares = Vec::new();
                    for j in 0..self.num_parties {
                        if j == self.id {
                            continue;
                        }

                        let mac_message = self.channels.listen.recv().unwrap();
                        if let Message {
                            from,
                            to,
                            payload: MessagePayload::WireMac(r_j, mac_j),
                        } = mac_message
                        {
                            // verify mac
                            let my_key = wire_share
                                .0
                                .mac_keys
                                .iter()
                                .find(|key| key.bit_holder == from)
                                .expect("should have keys for all other parties");
                            if !verify_mac(&r_j, &mac_j, &my_key.mac_key, &self.global_mac_key) {
                                return Err(Error::CheckFailed(
                                    "invalid nput wire MAC ".to_owned(),
                                ));
                            }
                            other_wire_mask_shares.push(r_j);
                        } else {
                            return Err(Error::UnexpectedMessage(mac_message));
                        }
                    }

                    // compute blinded input value
                    masked_wire_value = input_value ^ wire_share.0.bit.value;
                    for bit in other_wire_mask_shares {
                        masked_wire_value ^= bit;
                    }

                    // acknowledge received messages
                    for j in (0..self.num_parties).rev() {
                        if j == self.id {
                            continue;
                        }
                        self.channels.parties[j]
                            .send(Message {
                                from: self.id,
                                to: j,
                                payload: MessagePayload::Sync,
                            })
                            .unwrap();
                    }

                    // Broadcast masked wire. Don't care about other parties' values here.
                    self.broadcast(&vec![masked_wire_value as u8])?;
                } else {
                    // send input wire shares to the party
                    let their_mac = wire_share
                        .0
                        .macs
                        .iter()
                        .find(|(maccing_party, _)| *maccing_party == party)
                        .expect("should have macs from all other parties")
                        .1;
                    self.channels.parties[party]
                        .send(Message {
                            from: self.id,
                            to: party,
                            payload: MessagePayload::WireMac(wire_share.0.bit.value, their_mac),
                        })
                        .unwrap();

                    // receive acknowlegement
                    let sync_message = self.channels.listen.recv().unwrap();

                    if !(sync_message.from == party
                        && sync_message.to == self.id
                        && matches!(sync_message.payload, MessagePayload::Sync))
                    {
                        return Err(Error::UnexpectedMessage(sync_message));
                    }

                    // receive masked wire value broadcast
                    masked_wire_value = self
                        .broadcast(&[])?
                        .iter()
                        .find(|(sending_party, _)| *sending_party == party)
                        .expect("should have received broadcast from all other parties")
                        .1[0]
                        != 0;
                }

                masked_wire_values.push((input_wire_index, masked_wire_value));

                // Send correct wire label to evaluator.
                if self.is_evaluator() {
                    // listen for all wire labels
                    for _j in 0..self.num_parties - 1 {
                        let label_message = self.channels.listen.recv().unwrap();
                        if let Message {
                            from,
                            to,
                            payload: MessagePayload::WireLabel { wire, label },
                        } = label_message
                        {
                            debug_assert_eq!(to, self.id);
                            debug_assert_eq!(wire, input_wire_index);

                            wire_labels.push((from, wire, label));
                        } else {
                            return Err(Error::UnexpectedMessage(label_message));
                        }
                    }

                    // acknowledge received messages
                    for j in (0..self.num_parties).rev() {
                        if j == self.id {
                            continue;
                        }
                        self.channels.parties[j]
                            .send(Message {
                                from: self.id,
                                to: j,
                                payload: MessagePayload::Sync,
                            })
                            .unwrap();
                    }
                } else {
                    // send my wire label according to the received / computed wire_mask
                    let WireLabel(mut label) = wire_share
                        .clone()
                        .1
                        .expect("should have labels for all input wires");
                    if masked_wire_value {
                        label = xor_mac_width(&label, &self.global_mac_key)
                    }

                    self.channels
                        .evaluator
                        .send(Message {
                            from: self.id,
                            to: EVALUATOR_ID,
                            payload: MessagePayload::WireLabel {
                                wire: input_wire_index,
                                label,
                            },
                        })
                        .unwrap();

                    // listen for acknowledgement
                    let sync_message = self.channels.listen.recv().unwrap();

                    if !(sync_message.from == EVALUATOR_ID
                        && sync_message.to == self.id
                        && matches!(sync_message.payload, MessagePayload::Sync))
                    {
                        return Err(Error::UnexpectedMessage(sync_message));
                    }
                }
            }

            input_wire_offset += input_width;
        }

        Ok((masked_wire_values, wire_labels))
    }

    /// Run the circuit evaluation phase of the protocol.
    fn evaluate_circuit(
        &mut self,
        garbled_ands: Vec<GarbledAnd>,
        masked_input_wire_values: Vec<(usize, bool)>,
        input_wire_labels: Vec<(usize, usize, [u8; MAC_LENGTH])>,
    ) -> Result<(Vec<(usize, bool)>, Vec<(usize, usize, [u8; 16])>), Error> {
        let mut masked_wire_values = masked_input_wire_values;
        let mut wire_labels = input_wire_labels;
        for (gate_index, gate) in self.circuit.gates.iter().enumerate() {
            match *gate {
                crate::circuit::WiredGate::Input(_) => continue,
                crate::circuit::WiredGate::Xor(left, right) => {
                    let left_masked_value = masked_wire_values
                        .iter()
                        .find(|(wire_index, _)| *wire_index == left)
                        .expect("should have labels and mask for all earlier wires")
                        .1;
                    let right_masked_value = masked_wire_values
                        .iter()
                        .find(|(wire_index, _)| *wire_index == right)
                        .expect("should have labels and mask for all earlier wires")
                        .1;

                    let output_wire_mask = left_masked_value ^ right_masked_value;
                    masked_wire_values.push((gate_index, output_wire_mask));

                    for party in 1..self.num_parties {
                        let their_left_label = wire_labels
                            .iter()
                            .find(|(labeling_party, wire_index, _)| {
                                *labeling_party == party && *wire_index == left
                            })
                            .expect("should have labels from all parties for all earlier wires")
                            .2;
                        let their_right_label = wire_labels
                            .iter()
                            .find(|(labeling_party, wire_index, _)| {
                                *labeling_party == party && *wire_index == right
                            })
                            .expect("should have labels from all parties for all earlier wires")
                            .2;
                        let output_wire_label =
                            xor_mac_width(&their_left_label, &their_right_label);
                        wire_labels.push((party, gate_index, output_wire_label));
                    }
                }

                crate::circuit::WiredGate::And(left, right) => {
                    let output_wire_share = &self.wire_shares[gate_index]
                        .as_ref()
                        .expect("should have shares for all AND gates")
                        .0;
                    let left_masked_value = masked_wire_values
                        .iter()
                        .find(|(wire_index, _)| *wire_index == left)
                        .expect("should have labels and mask for all earlier wires")
                        .1;
                    let right_masked_value = masked_wire_values
                        .iter()
                        .find(|(wire_index, _)| *wire_index == right)
                        .expect("should have labels and mask for all earlier wires")
                        .1;

                    let mut masked_output_value = output_wire_share.bit.value;
                    let mut this_wires_labels = Vec::new();
                    for j in 1..self.num_parties {
                        let garble_index =
                            2 * (left_masked_value as u8) + (right_masked_value as u8);
                        // recover output wire shares and labels from garbled tables
                        let their_left_label = wire_labels
                            .iter()
                            .find(|(sender, gate_index, _)| *sender == j && *gate_index == left)
                            .expect("should have labels from all other parties")
                            .2;
                        let their_right_label = wire_labels
                            .iter()
                            .find(|(sender, gate_index, _)| *sender == j && *gate_index == right)
                            .expect("should have labels from all other parties")
                            .2;
                        let garbled_and_table = garbled_ands
                            .iter()
                            .find(|g| g.gate_index == gate_index && g.sender == j)
                            .expect("should habe garbled and from all parties for all and gates");
                        let garbled_and = match garble_index {
                            0 => &garbled_and_table.g0,
                            1 => &garbled_and_table.g1,
                            2 => &garbled_and_table.g2,
                            3 => &garbled_and_table.g3,
                            _ => panic!("Invalid garble index"),
                        };
                        let (r_j, macs, initial_output_label) = self.ungarble_and(
                            gate_index,
                            garble_index,
                            garbled_and,
                            their_left_label,
                            their_right_label,
                        )?;
                        // check my MAC on recovered share

                        let my_mac = macs[self.id];
                        let my_key = output_wire_share
                            .mac_keys
                            .iter()
                            .find(|k| k.bit_holder == j)
                            .expect("should have keys for all other parties' MACs");
                        if !verify_mac(&r_j, &my_mac, &my_key.mac_key, &self.global_mac_key) {
                            return Err(Error::CheckFailed(
                                "AND gate evaluation: MAC check failed".to_owned(),
                            ));
                        }
                        masked_output_value ^= r_j;
                        let mut their_output_wire_label = initial_output_label;
                        for mac in macs {
                            their_output_wire_label = xor_mac_width(&their_output_wire_label, &mac);
                        }
                        this_wires_labels.push((j, their_output_wire_label));
                        wire_labels.push((j, gate_index, their_output_wire_label));
                    }

                    masked_wire_values.push((gate_index, masked_output_value));
                }

                crate::circuit::WiredGate::Not(before) => {
                    let before_masked_value = masked_wire_values
                        .iter()
                        .find(|(wire_index, _)| *wire_index == before)
                        .expect("should have labels and mask for all earlier wires")
                        .1;
                    let output_wire_mask = before_masked_value ^ true;
                    masked_wire_values.push((gate_index, output_wire_mask));
                    for j in 1..self.num_parties {
                        let their_label = wire_labels
                            .iter()
                            .find(|(sender, gate_index, _)| *sender == j && *gate_index == before)
                            .expect("should have labels for all earlier wires")
                            .2;
                        wire_labels.push((j, gate_index, their_label)); // XXX: Label stays the same here. OK?
                    }
                }
            }
        }
        Ok((masked_wire_values, wire_labels))
    }

    /// Run the output processing phase of the protocol
    pub fn output_processing(&mut self) {
        todo!("the output processing phase is not yet implemented (cf. GitHub issue #53")
    }

    /// Run the MPC protocol, returning the parties output, if any.
    pub fn run(&mut self, read_stored_triples: bool) -> Result<Option<Vec<bool>>, Error> {
        use std::io::Write;

        let num_auth_shares = self.circuit.share_authentication_cost() + SEC_MARGIN_SHARE_AUTH;
        self.log(&format!(
            "Require {num_auth_shares} authenticated share(s) in total to evaluate circuit."
        ));

        if read_stored_triples {
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

                if num_auth_shares > self.abit_pool.len() {
                    self.log(&format!(
                        "Insufficient precomputation (by {})",
                        num_auth_shares - self.abit_pool.len()
                    ));
                    return Ok(None);
                }
            }
        } else {
            let target_number = self.circuit.share_authentication_cost();
            self.log(&format!(
                    "Pre-computing {target_number} + {SEC_MARGIN_SHARE_AUTH} maliciously secure bit authentication(s)..."
                ));

            self.abit_pool = self.precompute_abits(target_number + SEC_MARGIN_SHARE_AUTH)?;

            let file = std::fs::File::create(format!("{}.triples", self.id))
                .map_err(|_| Error::OtherError)?;
            let mut writer = std::io::BufWriter::new(file);
            serde_json::to_writer(&mut writer, &(self.global_mac_key, &self.abit_pool))
                .map_err(|_| Error::OtherError)?;
            writer.flush().unwrap();
        }

        self.function_independent().unwrap();
        let garbled_ands = self.function_dependent().unwrap();
        if self.is_evaluator() {
            debug_assert_eq!(
                garbled_ands.len(),
                self.circuit.num_and_gates() * (self.num_parties - 1)
            );
        }

        Ok(None)
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

    fn garble_and(
        &self,
        gate_index: usize,
        garble_index: u8,
        and_share: AuthBit,
        output_label: [u8; 16],
        left_label: [u8; 16],
        right_label: [u8; 16],
    ) -> Vec<u8> {
        let garble_serialization: Vec<u8> = self.garbling_serialize(and_share, output_label);
        let blinding: Vec<u8> = compute_blinding(
            garble_serialization.len(),
            left_label,
            right_label,
            gate_index,
            garble_index,
        );
        let mut result = vec![0u8; garble_serialization.len()];
        for byte in 0..result.len() {
            result[byte] = garble_serialization[byte] ^ blinding[byte];
        }
        result
    }

    fn ungarble_and(
        &self,
        gate_index: usize,
        garble_index: u8,
        garbled_and: &[u8],
        left_label: [u8; 16],
        right_label: [u8; 16],
    ) -> Result<(bool, Vec<[u8; MAC_LENGTH]>, [u8; MAC_LENGTH]), Error> {
        let blinding: Vec<u8> = compute_blinding(
            garbled_and.len(),
            left_label,
            right_label,
            gate_index,
            garble_index,
        );
        let mut result_bytes = vec![0u8; garbled_and.len()];
        for byte in 0..result_bytes.len() {
            result_bytes[byte] = garbled_and[byte] ^ blinding[byte];
        }

        self.garbling_deserialize(&result_bytes)
    }

    fn garbling_serialize(&self, and_share: AuthBit, output_label: [u8; 16]) -> Vec<u8> {
        let mut result = and_share.serialize_bit_macs();
        let mut garbled_label = output_label;
        for key in and_share.mac_keys {
            garbled_label = xor_mac_width(&garbled_label, &key.mac_key);
        }

        if and_share.bit.value {
            garbled_label = xor_mac_width(&garbled_label, &self.global_mac_key);
        }
        result.extend_from_slice(&garbled_label);
        result
    }

    fn garbling_deserialize(
        &self,
        serialization: &[u8],
    ) -> Result<(bool, Vec<[u8; 16]>, [u8; 16]), Error> {
        let (bit_mac_bytes, label) = serialization.split_at(1 + MAC_LENGTH * self.num_parties);
        let (bit_value, macs) = AuthBit::deserialize_bit_macs(bit_mac_bytes)?;
        Ok((bit_value, macs, label.try_into().unwrap()))
    }
}

fn compute_blinding(
    len: usize,
    left_label: [u8; 16],
    right_label: [u8; 16],
    gate_index: usize,
    garble_index: u8,
) -> Vec<u8> {
    let mut ikm = vec![garble_index];
    ikm.extend_from_slice(&left_label);
    ikm.extend_from_slice(&right_label);
    ikm.extend_from_slice(&gate_index.to_be_bytes());
    let domain_separator = "garble-blinding";
    let prekey = hkdf_extract(domain_separator.as_bytes(), &ikm);
    hkdf_expand(&prekey, b"", len)
}
