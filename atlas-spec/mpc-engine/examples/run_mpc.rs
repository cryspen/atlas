use std::thread;

use hacspec_lib::Randomness;
use mpc_engine::circuit::{Circuit, WiredGate};

use rand::RngCore;

fn build_circuit() -> Circuit {
    Circuit {
        input_widths: vec![1, 1, 1, 1],
        gates: vec![
            WiredGate::Input(0),  // Gate 0
            WiredGate::Input(1),  // Gate 1
            WiredGate::Input(2),  // Gate 2
            WiredGate::And(0, 1), // Gate 3
            WiredGate::And(3, 2), // Gate 4
        ],
        output_gates: vec![4],
    }
}
fn main() {
    let circuit = build_circuit();

    let num_parties = circuit.number_of_parties();

    // Set up channels
    let (broadcast_relay, mut party_channels) = mpc_engine::utils::set_up_channels(num_parties);

    let _ = thread::spawn(move || broadcast_relay.run());

    let mut party_join_handles = Vec::new();
    for _i in 0..num_parties {
        let channel_config = party_channels
            .pop()
            .expect("every party should have a channel configuration");
        let c = circuit.clone();
        let party_join_handle = thread::spawn(move || {
            let mut rng = rand::thread_rng();
            let mut bytes = vec![0u8; u16::MAX.try_into().unwrap()];
            rng.fill_bytes(&mut bytes);
            let rng = Randomness::new(bytes);
            let log_enabled = channel_config.id == 1;
            let mut p = mpc_engine::party::Party::new(channel_config, &c, log_enabled, rng);

            let _ = p.run();
        });
        party_join_handles.push(party_join_handle);
    }

    for _i in 0..num_parties {
        party_join_handles
            .pop()
            .expect("every party should have a join handle")
            .join()
            .expect("party did not panic");
    }
}
