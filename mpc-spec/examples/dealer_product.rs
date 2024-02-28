use std::thread;

use mpc_spec::circuit::{Circuit, WiredGate};

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
    let (fpre_channel_config, mut party_channels) =
        mpc_spec::utils::set_up_channels_ideal(num_parties);

    let fpre_join_handle = thread::spawn(move || {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        let rng = mpc_spec::utils::rand::Randomness::new(bytes.to_vec());
        let mut fpre = mpc_spec::utils::ideal_fpre::FPre::new(fpre_channel_config, rng);
        let _ = fpre.run();
    });

    let mut party_join_handles = Vec::new();
    for _i in 0..num_parties {
        let channel_config = party_channels
            .pop()
            .expect("every party should have a channel configuration");
        let c = circuit.clone();
        let party_join_handle = thread::spawn(move || {
            let bytes = vec![0, 1, 2, 3];
            let rng = mpc_spec::utils::rand::Randomness::new(bytes);
            let mut p = mpc_spec::party::Party::new(channel_config, &c, rng);

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

    // fpre_tx.send(MPCMessage::FPreDone).unwrap();
    fpre_join_handle.join().expect("FPre should shut down")
}
