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
/// - `listen`: The parties on message receiver handle
/// - `evaluator`: The sender handle for the designated evaluator party
/// - `parties`: All other parties' sender handles, ordered by their `id`s
/// - `id`: The owning parties `id`
#[allow(dead_code)] // TODO: Remove this later.
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
    /// The parties numeric identifier
    id: usize,
    /// For ease of reference: number of parties in the session
    num_parties: usize,
    /// The channel configuration for communicating to other protocol parties
    channels: ChannelConfig,
    /// The global MAC key for authenticating bit shares
    global_mac_key: MacKey,
    /// The circuit to be evaluated during the multi-party computation
    circuit: Circuit,
    /// A source of random bytes and bits local to the party
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
            global_mac_key: generate_mac_key(&mut entropy).unwrap(),
            circuit: circuit.clone(),
            entropy,
            current_phase: ProtocolPhase::PreInit,
            log_counter: 0,
            enable_logging: logging,
        }
    }

    /// Broadcast a `value` and receive other parties' broadcasted values in
    /// turn.
    fn broadcast(&mut self, value: &[u8]) -> Result<Vec<(usize, Vec<u8>)>, Error> {
        // send/receive commitment to/from all parties
        let dst = b"Broadcast";
        let (my_commitment, my_opening) = Commitment::new(value, dst, &mut self.entropy)?;

        let mut commitments = Vec::new();
        // Expect earlier parties' commitments.
        for _i in 0..self.id {
            let commitment = self.channels.listen.recv().unwrap();
            if let MessagePayload::BroadcastCommitment(c) = commitment.payload {
                assert_eq!(commitment.to, self.id);
                commitments.push((commitment.from, c));
            } else {
                return Err(Error::UnexpectedMessage(commitment));
            }
        }

        // All earlier messages have been received, so it is the parties' turn
        // to send messages to everyone, except itself.
        for i in 0..self.num_parties {
            if i == self.id {
                continue;
            }

            self.channels.parties[i]
                .send(Message {
                    from: self.id,
                    to: i,
                    payload: MessagePayload::BroadcastCommitment(my_commitment.clone()),
                })
                .unwrap();
        }

        // Wait for the messages sent by later parties.
        for _i in self.id + 1..self.num_parties {
            let commitment = self.channels.listen.recv().unwrap();
            if let MessagePayload::BroadcastCommitment(c) = commitment.payload {
                assert_eq!(commitment.to, self.id);
                commitments.push((commitment.from, c));
            } else {
                return Err(Error::UnexpectedMessage(commitment));
            }
        }

        self.sync().unwrap();

        // Send the opening to the broadcast utility
        let log_opening = Message {
            from: self.id,
            to: self.id,
            payload: MessagePayload::BroadcastOpening(my_opening),
        };
        self.channels.broadcast.send(log_opening).unwrap();

        // receive n-1 broadcast openings
        let mut results = Vec::new();
        for _i in 0..self.num_parties - 1 {
            let opening_msg = self.channels.listen.recv().unwrap();
            if let MessagePayload::BroadcastOpening(ref o) = opening_msg.payload {
                let c = &commitments
                    .iter()
                    .find(|(i, _c)| *i == opening_msg.from)
                    .expect("should get opening from all parties")
                    .1;
                let their_value = c.open(o)?;
                results.push((opening_msg.from, their_value));
            } else {
                return Err(Error::UnexpectedMessage(opening_msg));
            }
        }
        // send opening to broadcast log
        // send open_ack to all parties
        // retrieve opening from broadcast log
        self.sync().unwrap();
        Ok(results)
    }

    /// Return `true`, if the party is the designated circuit evaluator.
    fn is_evaluator(&self) -> bool {
        self.id == 0
    }

    /// Send a message to the evaluator.
    fn send_to_evaluator(&mut self, message: Message) {
        self.channels.evaluator.send(message).unwrap();
    }

    /// Jointly compute `len` bit authentications.
    fn bit_auth(&mut self, len: usize) -> Result<Vec<AuthBit>, Error> {
        // 1. Set `ell' := len + 2*rho` and sample `ell'` random bits.
        let ell_prime = len + 2 * STATISTICAL_SECURITY * 8;

        let raw_bits = self.entropy.bytes(ell_prime / 8 + 1)?.to_owned();
        let mut bits = Vec::new();

        for i in 0..ell_prime {
            bits.push(Bit {
                id: self.fresh_bit_id(),
                value: ith_bit(i, &raw_bits),
            })
        }

        // 2. Get MACs on all bits from every other party and provide MACs on
        //    their bits.
        let mut auth_bits = Vec::new();
        for (bit_index, bit) in bits.into_iter().enumerate() {
            let mut authenticators: Vec<BitKey> = Vec::new();
            let mut macs = Vec::new();

            for i in 0..self.id {
                let key_i = self.abit_2pc_responder(i)?;
                authenticators.push(key_i)
            }

            for i in 0..self.num_parties {
                if i == self.id {
                    continue;
                }

                let mac: Mac = self.abit_2pc_initiator(i, &bit)?;
                macs.push((i, mac));
            }

            for i in self.id + 1..self.num_parties {
                let key_i = self.abit_2pc_responder(i)?;
                authenticators.push(key_i)
            }

            self.sync().unwrap();

            self.log(&format!(
                "Completed a bit authentication [{}/{}]",
                bit_index + 1,
                ell_prime
            ));

            auth_bits.push(AuthBit {
                bit,
                macs,
                authenticators,
            })
        }

        self.sync().unwrap();

        // 3. Check validity of authenticated bits
        self.bit_auth_check(&auth_bits)
            .expect("cheating detected during bit authentication");

        // 4. Return the first `len` bit authentications
        Ok(auth_bits[0..len].to_vec())
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
                assert!(other_x_j.len() == 1);
                other_x_js.push((party, other_x_j[0] != 0))
            }

            self.sync().unwrap();

            // c) Compute xored keys for other parties
            let mut xored_keys = vec![[0u8; MAC_LENGTH]; self.num_parties];
            let mut xored_tags = vec![[0u8; MAC_LENGTH]; self.num_parties];
            for (m, xm) in auth_bits.iter().enumerate() {
                if ith_bit(m, &r) {
                    for mac_keys in xm.authenticators.iter() {
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
                let mac_message = self.channels.listen.recv().unwrap();
                if let MessagePayload::Mac(mac) = mac_message.payload {
                    assert_eq!(mac_message.to, self.id, "Wrong recipient for MAC message");
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
                self.channels.parties[i].send(mac_message).unwrap();
            }

            for _i in self.id + 1..self.num_parties {
                let mac_message = self.channels.listen.recv().unwrap();
                if let MessagePayload::Mac(mac) = mac_message.payload {
                    assert_eq!(mac_message.to, self.id, "Wrong recipient for MAC message");
                    received_macs.push((mac_message.from, mac));
                } else {
                    return Err(Error::UnexpectedMessage(mac_message));
                }
            }

            self.sync().unwrap();

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
        let my_contribution = self.entropy.bytes(len / 8 + 1)?.to_owned();
        let other_contributions = self.broadcast(&my_contribution)?;

        let mut result = my_contribution;
        for (_party, their_contribution) in other_contributions {
            assert_eq!(
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
        their_sender: Sender<SubMessage>,
        own_receiver: Receiver<SubMessage>,
        their_id: usize,
        left_input: &[u8],
        right_input: &[u8],
    ) -> Result<(), Error> {
        // let (own_sender, own_receiver) = mpsc::channel::<SubMessage>();
        // let (their_sender, their_receiver) = mpsc::channel::<SubMessage>();

        // let channel_msg = Message {
        //     from: self.id,
        //     to: their_id,
        //     payload: MessagePayload::SubChannel(own_sender, their_receiver),
        // };
        // self.channels.parties[their_id].send(channel_msg).unwrap();

        let dst = format!("OT-{}-{}", self.id, their_id);
        let (ot_sender, ot_commit) =
            crate::primitives::ot::OTSender::init(&mut self.entropy, dst.as_bytes())?;
        their_sender.send(SubMessage::OTCommit(ot_commit)).unwrap();
        let receiver_msg = own_receiver.recv().unwrap();

        if let SubMessage::OTSelect(selection) = receiver_msg {
            let send = ot_sender.send(left_input, right_input, &selection, &mut self.entropy)?;

            their_sender.send(SubMessage::OTSend(send)).unwrap();
            Ok(())
        } else {
            Err(Error::UnexpectedSubprotocolMessage(receiver_msg))
        }
    }

    /// Listen for an OT initiation as the receiver.
    ///
    /// The receiver needs to provide a choice of left or right output to the
    /// protocol and receives the chosen sender input.
    fn ot_receive(
        &mut self,
        choose_left: bool,
        their_channel: Sender<SubMessage>,
        my_channel: Receiver<SubMessage>,
        their_id: usize,
    ) -> Result<Vec<u8>, Error> {
        let first_msg = my_channel.recv().unwrap();
        if let SubMessage::OTCommit(commitment) = first_msg {
            let dst = format!("OT-{}-{}", their_id, self.id);
            let (receiver, resp) = crate::primitives::ot::OTReceiver::select(
                &mut self.entropy,
                dst.as_bytes(),
                commitment,
                choose_left,
            )?;
            their_channel.send(SubMessage::OTSelect(resp)).unwrap();
            let second_msg = my_channel.recv().unwrap();
            if let SubMessage::OTSend(payload) = second_msg {
                let result = receiver.receive(payload)?;
                Ok(result)
            } else {
                Err(Error::UnexpectedSubprotocolMessage(second_msg))
            }
        } else {
            Err(Error::UnexpectedSubprotocolMessage(first_msg))
        }

        // let channel_msg = self.channels.listen.recv().unwrap();

        // if let Message {
        //     to,
        //     from,
        //     payload: MessagePayload::SubChannel(their_channel, my_channel),
        // } = channel_msg
        // {
        //     let first_msg = my_channel.recv().unwrap();
        //     if let SubMessage::OTCommit(commitment) = first_msg {
        //         let dst = format!("OT-{}-{}", from, to);
        //         self.log(&format!("Choose left input: {choose_left}"));
        //         let (receiver, resp) = crate::primitives::ot::OTReceiver::select(
        //             &mut self.entropy,
        //             dst.as_bytes(),
        //             commitment,
        //             choose_left,
        //         )?;
        //         their_channel.send(SubMessage::OTSelect(resp)).unwrap();
        //         let second_msg = my_channel.recv().unwrap();
        //         if let SubMessage::OTSend(payload) = second_msg {
        //             assert_eq!(self.id, to);
        //             let result = receiver.receive(payload)?;
        //             self.log(&format!("Got message {result:?}"));
        //             Ok(result)
        //         } else {
        //             Err(Error::UnexpectedSubprotocolMessage(second_msg))
        //         }
        //     } else {
        //         Err(Error::UnexpectedSubprotocolMessage(first_msg))
        //     }
        // } else {
        //     Err(Error::UnexpectedMessage(channel_msg))
        // }
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
        self.channels.parties[i].send(channel_msg).unwrap();

        let dst = format!("EQ-{}-{}", self.id, i);
        let (commitment, opening) = Commitment::new(my_value, dst.as_bytes(), &mut self.entropy)?;
        their_sender.send(SubMessage::EQCommit(commitment)).unwrap();

        let responder_message = own_receiver.recv().unwrap();
        if let SubMessage::EQResponse(their_value) = responder_message {
            let res = their_value == my_value;
            their_sender.send(SubMessage::EQOpening(opening)).unwrap();
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
        let channel_msg = self.channels.listen.recv().unwrap();

        if let Message {
            to,
            from: _from,
            payload: MessagePayload::SubChannel(their_channel, my_channel),
        } = channel_msg
        {
            assert_eq!(to, self.id);
            let commit_message = my_channel.recv().unwrap();
            if let SubMessage::EQCommit(commitment) = commit_message {
                their_channel
                    .send(SubMessage::EQResponse(my_value.to_vec()))
                    .unwrap();
                let opening_message = my_channel.recv().unwrap();
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

    /// Generate a fresh bit id.
    fn fresh_bit_id(&mut self) -> BitID {
        let res = self.bit_counter;
        self.bit_counter += 1;
        BitID(res)
    }

    /// Initiate a bit authentication session.
    fn abit_2pc_initiator(&mut self, i: usize, bit: &Bit) -> Result<Mac, Error> {
        let (own_sender, own_receiver) = mpsc::channel::<SubMessage>();
        let (their_sender, their_receiver) = mpsc::channel::<SubMessage>();

        let req_msg = Message {
            from: self.id,
            to: i,
            payload: MessagePayload::RequestBitAuth(bit.id.clone(), own_sender, their_receiver),
        };

        self.channels.parties[i].send(req_msg).unwrap();

        let mac: Mac = self
            .ot_receive(bit.value, their_sender, own_receiver, i)?
            .try_into()
            .expect("should receive a MAC of the right length");

        Ok(mac)
    }

    /// Listen for a bit authentication initiation.
    fn abit_2pc_responder(&mut self, bit_holder: usize) -> Result<BitKey, Error> {
        let req_msg = self.channels.listen.recv().unwrap();

        if let Message {
            to,
            from,
            payload: MessagePayload::RequestBitAuth(id, their_sender, own_receiver),
        } = req_msg
        {
            assert_eq!(to, self.id, "Got a wrongly addressed message");

            let (mac_key_and_global, mac_key) =
                mac(&true, &self.global_mac_key, &mut self.entropy)?;

            self.ot_send(
                their_sender,
                own_receiver,
                from,
                &mac_key_and_global,
                &mac_key,
            )?;

            Ok(BitKey {
                id,
                bit_holder,
                mac_key,
            })
        } else {
            self.log(&format!("Bit Auth: Unexpected message {req_msg:?}"));
            Err(Error::UnexpectedMessage(req_msg))
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
        let _auth_bits = self.bit_auth(1)?;

        Ok(None)
    }

    /// Synchronise parties.
    fn sync(&self) -> Result<(), Error> {
        for _i in (self.id + 1..self.num_parties).rev() {
            let sync_msg = self.channels.listen.recv().unwrap();
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
                .unwrap();
        }

        for _ in (0..self.id).rev() {
            let sync_msg = self.channels.listen.recv().unwrap();
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
