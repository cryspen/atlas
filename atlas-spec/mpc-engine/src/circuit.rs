//! The [`Circuit`] representation used by the MPC engine.
//!
//! A circuit is made up of logic gates and value-carrying wires between the
//! gates. Each gate takes one or more wires as input, depending on the type of
//! gate, and has exactly one output wire.
//!
//! Conceptually, a circuit is a sequence of input or logic (XOR/AND/NOT) gates,
//! with all input gates at the beginning of the sequence, followed by all logic
//! gates. The index of a gate in the sequence determines its "wire index",
//! which is available as the input to any gate later in the sequence. For
//! example, in a circuit with two input gates (1 bit for party A, 1 bit for
//! party B), followed by three logic gates (an XOR of the two input gates, an
//! AND of the two input gates, and an XOR of these two XOR/AND gates), the
//! input gates would be the wires 0 and 1, the XOR of these two input gates
//! would be specified as `Gate::Xor(0, 1)` and have wire index 2, the AND of
//! the two input gates would be specified as `Gate::And(0, 1)` and have wire
//! index 3, and the XOR of the two logic gates would be specified as
//! `Gate::Xor(2, 3)` and have wire index 4:
//!
//! ```text
//! Input A (Wire 0) ----+----------+
//!                      |          |
//! Input B (Wire 1) ----|-----+----|-----+
//!                      |     |    |     |
//!                      +-XOR-+    |     |
//!         (Wire 2) =====> |       |     |
//!                         |       +-AND-+
//!         (Wire 3) =======|========> |
//!                         +---XOR----+
//!         (Wire 4) ==========> |
//! ```
//!
//! The input gates of different parties cannot be interleaved: Each party must
//! supply all of their inputs before the next party's inputs can start.
//!
//! At least one input bit must be specified, and every party contributing
//! inputs to the circuit has to specify at least one input bit. Party input
//! gates may not refer to other input gates' wire indices.
//!
//! This module is derived from the circuit representation of
//! [`garble_lang`](https://github.com/sine-fdn/garble-lang/tree/main), the
//! license of which is reproduced below.
//!
//! > MIT License
//! >
//! > Copyright (c) 2022 SINE e.V.
//! >
//! > Permission is hereby granted, free of charge, to any person obtaining a
//! > copy of this software and associated documentation files (the "Software"),
//! > to deal in the Software without restriction, including without limitation
//! > the rights to use, copy, modify, merge, publish, distribute, sublicense,
//! > and/or sell copies of the Software, and to permit persons to whom the
//! > Software is furnished to do so, subject to the following conditions:
//! >
//! > The above copyright notice and this permission notice shall be included in
//! > all copies or substantial portions of the Software.
//! >
//! > THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//! > IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//! > FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
//! > THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//! > LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//! > FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! > DEALINGS IN THE SOFTWARE.
//!
//!

use crate::{party::SEC_MARGIN_SHARE_AUTH, STATISTICAL_SECURITY};

/// Data type to uniquely identify gate output wires.
pub type WireIndex = usize;

/// An input gate or a logic gate with its input wire specification.
#[derive(Debug, Clone)]
pub enum WiredGate {
    /// An input wire, with its value coming directly from one of the parties.
    /// Its [`WireIndex`] must refer to its own gate index.
    Input(WireIndex),
    /// A logical XOR gate attached to the two specified input wires. The
    /// [`WireIndex`] of each input wire must refer to a lower index than the
    /// gate's own index.
    Xor(WireIndex, WireIndex),
    /// A logical AND gate attached to the two specified input wires. The
    /// [`WireIndex`] of each input wire must refer to a lower index than the
    /// gate's own index.
    And(WireIndex, WireIndex),
    /// A logical NOT gate attached to the specified input wire. The
    /// [`WireIndex`] of the input wire must refer to a lower index than the
    /// gate's own index.
    Not(WireIndex),
}

/// Specifies how many input bits a party is expected to contribute to the
/// evaluation.
pub type InputWidth = usize;
/// Representation of a circuit evaluated by an MPC engine.
#[derive(Debug, Clone)]
pub struct Circuit {
    /// The bit-width of the inputs expected by the different parties,
    /// [`InputWidth`] at index `i` representing the number of input bits for
    /// party `i`.
    pub input_widths: Vec<InputWidth>,
    /// The circuit's gates.
    pub gates: Vec<WiredGate>,
    /// The indices of the gates in [`Circuit::gates`] that produce output bits.
    pub output_gates: Vec<WireIndex>,
}

/// Errors occurring during the validation or the execution of the MPC protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum CircuitError {
    /// The provided party input does not match the number of input bits for
    /// that party expected by the circuit.
    PartyInputMismatch(usize, usize),
    /// The provided set of inputs does not match the number of party inputs
    /// expected by the circuit.
    PartyCountMismatch(usize, usize),
    /// The gate with the specified wire index contains invalid gate connections
    /// or is placed out of sequence.
    InvalidGate(usize),
    /// The specified output gate does not exist in the circuit.
    InvalidOutputWire(usize),
    /// The circuit does not specify any output gates.
    EmptyOutputSpecification,
    /// The circuit does not specify input wires.
    EmptyInputSpecification,
    /// The circuit specifies a zero-width input.
    InvalidInputSpecification,
}

impl std::fmt::Display for CircuitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitError::PartyInputMismatch(expected_inputs, actual_inputs) => write!(
                f,
                "expected {} input bits for a party, but received {} input bits",
                *expected_inputs, *actual_inputs
            ),
            CircuitError::PartyCountMismatch(expected_parties, actual_parties) => write!(
                f,
                "expected inputs for {} parties, but received inputs for {} parties",
                *expected_parties, *actual_parties
            ),
            CircuitError::InvalidGate(gate_index) => write!(
                f,
                "found out of order placement or invalid wiring at gate index {}",
                *gate_index
            ),
            CircuitError::InvalidOutputWire(oob_index) => {
                write!(f, "output index {} is out of bounds", *oob_index)
            }
            CircuitError::EmptyOutputSpecification => {
                write!(f, "circuit does not specify output bits")
            }
            CircuitError::EmptyInputSpecification => {
                write!(f, "circuit does not specify any party inputs")
            }
            CircuitError::InvalidInputSpecification => {
                write!(f, "circuit specifies an empty party input")
            }
        }
    }
}

impl Circuit {
    /// Number of parties expected to contribute inputs to the circuit.
    pub fn number_of_parties(&self) -> usize {
        self.input_widths.len()
    }

    /// Check validity of circuit specification.
    ///
    /// In particular:
    /// * Validate input specification: Input width specification does not allow
    ///   0-width inputs and at least one party must provide input bits.
    /// * Validate gate sequence: All input gates must be at the beginning of
    ///   the gate sequence, followed only by logic gates.
    /// * Validate gate wiring: A logic gate with index `i` can only take input
    ///   wires with strictly smaller indices. An input gate with index `i` must
    ///   refer to its own index as the input wire index.
    /// * Validate output specification: The number of specified output wires
    ///  must be non-zero and all output wire indices must refer to valid wire
    ///  indices in the circuit, i.e. output wire indices must be smaller or
    ///  equal to the highest wire index used in the circuit.
    pub fn validate_circuit_specification(&self) -> Result<(), CircuitError> {
        // Check input validity.
        if self.input_widths.is_empty() {
            return Err(CircuitError::EmptyInputSpecification);
        }
        for input_width in &self.input_widths {
            if *input_width == 0 {
                return Err(CircuitError::InvalidInputSpecification);
            }
        }

        // Check gate and gate sequence validity.
        let mut total_input_width = 0;
        for party_input_width in &self.input_widths {
            total_input_width += party_input_width;
        }

        for (gate_index, gate) in self.gates.iter().enumerate() {
            match *gate {
                WiredGate::Input(x) => {
                    if x != gate_index || gate_index >= total_input_width {
                        return Err(CircuitError::InvalidGate(gate_index));
                    }
                }
                WiredGate::Xor(x, y) => {
                    if x >= gate_index || y >= gate_index || gate_index < total_input_width {
                        return Err(CircuitError::InvalidGate(gate_index));
                    }
                }
                WiredGate::And(x, y) => {
                    if x >= gate_index || y >= gate_index || gate_index < total_input_width {
                        return Err(CircuitError::InvalidGate(gate_index));
                    }
                }
                WiredGate::Not(x) => {
                    if x >= gate_index || gate_index < total_input_width {
                        return Err(CircuitError::InvalidGate(gate_index));
                    }
                }
            }
        }

        // Validate non-empty output specification.
        if self.output_gates.is_empty() {
            return Err(CircuitError::EmptyOutputSpecification);
        }

        // Validate output wire bounds.
        for &output_wire in &self.output_gates {
            if output_wire >= self.gates.len() {
                return Err(CircuitError::InvalidOutputWire(output_wire));
            }
        }

        Ok(())
    }

    /// Validate that a given set of party inputs corresponds to the circuit
    /// specification.
    ///
    /// In particular:
    /// * Validate that the number of input vectors corresponds to the number of parties
    ///   expected to provide inputs.
    /// * Validate, for each input vector, that the number of input bits matches the
    ///   corresponding parties' expected input width.
    pub fn validate_input_vectors(&self, inputs: &[Vec<bool>]) -> Result<(), CircuitError> {
        if self.number_of_parties() != inputs.len() {
            return Err(CircuitError::PartyCountMismatch(
                self.number_of_parties(),
                inputs.len(),
            ));
        }

        for (party, &expected_input_gates) in self.input_widths.iter().enumerate() {
            if expected_input_gates != inputs[party].len() {
                return Err(CircuitError::PartyInputMismatch(
                    expected_input_gates,
                    inputs[party].len(),
                ));
            }
        }

        Ok(())
    }

    /// Evaluates a circuit with the specified inputs (with one `Vec<bool>` per
    /// party).
    ///
    /// After validation of the circuit specification and validation of the
    /// provided input vectors, the circuit is evaluated gate by gate:
    ///
    /// * Input gates are evaluated as the identity function on the provided
    ///   input.
    /// * Logic gates are evaluated by applying the given logical operation to
    ///   the wire values of the gates' input wires.
    ///
    /// Circuit validation ensures that, during sequential evaluation, gate
    /// input wires can only refer to previously evaluated gates, or values
    /// provided in the circuit inputs in the case of input gate evaulation.
    ///
    /// The circuit output is packed into a bitstring, with the indicated output
    /// wire values appearing in sequential order.
    pub fn eval(&self, inputs: &[Vec<bool>]) -> Result<Vec<bool>, CircuitError> {
        self.validate_circuit_specification()?;
        self.validate_input_vectors(inputs)?;

        let mut wire_evaluations: Vec<bool> = inputs.iter().flat_map(|b| b.clone()).collect();

        for gate in &self.gates {
            let output_bit = match gate {
                WiredGate::Input(x) => wire_evaluations[*x],
                WiredGate::Xor(x, y) => wire_evaluations[*x] ^ wire_evaluations[*y],
                WiredGate::And(x, y) => wire_evaluations[*x] & wire_evaluations[*y],
                WiredGate::Not(x) => !wire_evaluations[*x],
            };
            wire_evaluations.push(output_bit);
        }

        let mut output_packed: Vec<bool> = Vec::with_capacity(self.output_gates.len());
        for output_gate in &self.output_gates {
            output_packed.push(wire_evaluations[*output_gate]);
        }
        Ok(output_packed)
    }

    /// Returns the number of gates (i.e. the size) of the circuit.
    pub fn num_gates(&self) -> usize {
        self.gates.len()
    }

    /// Computes the required bucket size for leaky AND triple combination.
    pub fn and_bucket_size(&self) -> usize {
        let and_bucket_size = (STATISTICAL_SECURITY as u32 / self.num_gates().ilog2()) as usize;
        and_bucket_size
    }

    /// Returns the number of AND gates in the circuit.
    pub fn num_and_gates(&self) -> usize {
        self.gates
            .iter()
            .filter(|gate| matches!(gate, WiredGate::And(_, _)))
            .count()
    }
    /// Computes the total number of share authentications that will be necessary
    /// to evaluate this circuit using the MPC protocol, excluding malicious security overhead.
    pub fn share_authentication_cost(&self) -> usize {
        let mut result: usize = 0;

        for party_input_width in self.input_widths.iter() {
            result += party_input_width;
        }

        let num_and_gates = self
            .gates
            .iter()
            .filter(|gate| matches!(gate, WiredGate::And(_, _)))
            .count();

        result += num_and_gates;
        result += num_and_gates * 3 * self.and_bucket_size();

        result
    }
}
