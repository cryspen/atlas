//! This module defines the behaviour of protocol parties in the different
//! phases of the protocol.

use hacspec_lib::Randomness;

use crate::{
    circuit::Circuit,
    messages::{Message, MessagePayload, SubMessage},
    primitives::{
        auth_share::{AuthBit, Bit, BitID, BitKey},
        commitment::Commitment,
        mac::{generate_mac_key, mac, verify_mac, Mac, MacKey, MAC_LENGTH},
    },
    utils::ith_bit,
    Error, STATISTICAL_SECURITY,
};
use std::sync::mpsc::{self, Receiver, Sender};

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
    /// Internally generates `len + 2 * STATISTICAL_SECURITY * 8` bit
    /// authentications for each other party, of which all but `len` are
    /// discarded after performing statistical checks for malicious security.
    /// After this point the guarantee is that a pair-wise consistent
    /// `global_mac_key` was used in all bit-authentications between two
    /// parties.
    fn multiparty_authenticate(&mut self, len: usize) -> Result<Vec<AuthBit>, Error> {
        let len_unchecked = len + 2 * STATISTICAL_SECURITY * 8;

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

    /// Perform the active_security check for bit authentication
    fn bit_auth_check(&mut self, auth_bits: &[AuthBit]) -> Result<(), Error> {
        for j in 0..2 * STATISTICAL_SECURITY * 8 {
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

            for (bit_holder, xored_key) in xored_keys.iter().enumerate() {
                self.log(&format!(
                    "Computed local key for party {}: {:?}",
                    bit_holder, xored_key
                ))
            }

            for (key_holder, xored_tag) in xored_tags.iter().enumerate() {
                self.log(&format!(
                    "Computed xored MAC for party {}: {:?}",
                    key_holder, xored_tag
                ))
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
                2 * STATISTICAL_SECURITY * 8
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
    pub fn run(&mut self) -> Result<Option<Vec<bool>>, Error> {
        let _auth_bits = self.multiparty_authenticate(1)?;

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
}
