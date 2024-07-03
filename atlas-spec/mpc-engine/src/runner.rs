//! This module implements a local MPC runner.
use std::{sync::mpsc, thread};

use hacspec_lib::Randomness;
use rand::RngCore;

use crate::circuit::Circuit;

/// A local runner for an MPC session based on MPSC channels.
pub struct Runner;

impl Runner {
    /// Set up and run an MPC session of the given circuit with the provided
    /// inputs.
    pub fn run(
        circuit: &Circuit,
        inputs: &[&[bool]],
        logging: Vec<usize>,
    ) -> Vec<Option<Vec<(usize, bool)>>> {
        let num_parties = inputs.len();
        let (broadcast_relay, party_channels) = crate::utils::set_up_channels(num_parties);

        let _ = thread::spawn(move || broadcast_relay.run());
        let mut results = vec![None; num_parties];

        let (sender, receiver) = mpsc::channel();

        let mut party_join_handles = Vec::new();
        for config in party_channels.into_iter() {
            let input = inputs[config.id].to_owned();
            let logging = logging.contains(&config.id);
            let c = circuit.clone();
            let sender = sender.clone();
            let party_join_handle = thread::spawn(move || {
                let mut rng = rand::thread_rng();
                let mut bytes = vec![0u8; 100 * usize::from(u16::MAX)];
                rng.fill_bytes(&mut bytes);
                let rng = Randomness::new(bytes);
                eprintln!("Starting party {} with input: {:?}", config.id, input);
                let mut p = crate::party::Party::new(config, &c, logging, rng);
                let result = p.run(&c, &input).unwrap();
                sender.send(result).unwrap();
            });
            party_join_handles.push(party_join_handle);
        }

        for _i in 0..num_parties {
            let (party, result) = receiver.recv().unwrap();

            results[party] = result;
        }

        for _i in 0..num_parties {
            party_join_handles
                .pop()
                .expect("every party should have a join handle")
                .join()
                .expect("party did not panic");
        }
        results
    }
}
