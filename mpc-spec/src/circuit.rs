//! The [`Circuit`] representation used by the MPC engine.
//!
//! This module is derived from the circuit representation of
//! [`garble_lang`](https://github.com/sine-fdn/garble-lang/tree/main),
//! the license of which is reproduced below.
//!
//! MIT License
//!
//! Copyright (c) 2022 SINE e.V.
//!
//! Permission is hereby granted, free of charge, to any person
//! obtaining a copy of this software and associated documentation
//! files (the "Software"), to deal in the Software without
//! restriction, including without limitation the rights to use, copy,
//! modify, merge, publish, distribute, sublicense, and/or sell copies
//! of the Software, and to permit persons to whom the Software is
//! furnished to do so, subject to the following conditions:
//!
//! The above copyright notice and this permission notice shall be
//! included in all copies or substantial portions of the Software.
//!
//! THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
//! EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
//! MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
//! NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
//! HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
//! WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//! OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//! DEALINGS IN THE SOFTWARE.
//!

/// Data type to uniquely identify gates.
pub type GateIndex = usize;

/// Description of a gate executed under MPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gate {
    /// A logical XOR gate attached to the two specified input wires.
    Xor(GateIndex, GateIndex),
    /// A logical AND gate attached to the two specified input wires.
    And(GateIndex, GateIndex),
    /// A logical NOT gate attached to the specified input wire.
    Not(GateIndex),
}

/// Representation of a circuit evaluated by an MPC engine.
///
/// Each circuit consists of 3 parts:
///
///   1. `input_gates`, specifying how many input bits each party must provide
///   2. `gates`, XOR/AND/NOT intermediate gates (with input gates or intermediate gates as inputs)
///   3. `output_gates`, specifying which gates should be exposed as outputs (and in which order)
///
/// Conceptually, a circuit is a sequence of input or intermediate (XOR/AND/NOT) gates, with all
/// input gates at the beginning of the sequence, followed by all intermediate gates. The index of a
/// gate in the sequence determines its "wire". For example, in a circuit with two input gates (1
/// bit for party A, 1 bit for party B), followed by three intermediate gates (an XOR of the two
/// input gates, an AND of the two input gates, and an XOR of these two intermediate XOR/AND gates),
/// the input gates would be the wires 0 and 1, the XOR of these two input gates would be specified
/// as `Gate::Xor(0, 1)` and have the wire 2, the AND of the two input gates would be specified as
/// `Gate::And(0, 1)` and have the wire 3, and the XOR of the two intermediate gates would be
/// specified as `Gate::Xor(2, 3)` and have the wire 4:
///
/// ```text
/// Input A (Wire 0) ----+----------+
///                      |          |
/// Input B (Wire 1) ----|-----+----|-----+
///                      |     |    |     |
///                      +-XOR-+    |     |
///         (Wire 2) =====> |       |     |
///                         |       +-AND-+
///         (Wire 3) =======|========> |
///                         +---XOR----+
///         (Wire 4) ==========> |
/// ```
///
/// The input gates of different parties cannot be interleaved: Each party must supply all of their
/// inputs before the next party's inputs can start. Consequently, a circuit with 16 input bits from
/// party A, 8 input bits from party B and 1 input bit from party C would be specified as an
/// `input_gates` field of `vec![16, 8, 1]`.
///
/// At least 1 input bit must be specified, not just because a circuit without inputs would not be
/// very useful, but also because the first two intermediate gates of every circuit are constant
/// true and constant false, specified as `Gate::Xor(0, 0)` with wire `n` and `Gate::Not(n)` (and
/// thus depend on the first input bit for their specifications).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Circuit {
    /// The different parties, with `usize` at index `i` as the number of input bits for party `i`.
    pub input_gates: Vec<usize>,
    /// The non-input intermediary gates.
    pub gates: Vec<Gate>,
    /// The indices of the gates in [`Circuit::gates`] that produce output bits.
    pub output_gates: Vec<GateIndex>,
}

/// An input wire or a gate operating on them.
pub enum Wire {
    /// An input wire, with its value coming directly from one of the parties.
    Input(GateIndex),
    /// A logical XOR gate attached to the two specified input wires.
    Xor(GateIndex, GateIndex),
    /// A logical AND gate attached to the two specified input wires.
    And(GateIndex, GateIndex),
    /// A logical NOT gate attached to the specified input wire.
    Not(GateIndex),
}

/// Errors occurring during the validation or the execution of the MPC protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum CircuitError {
    /// The gate with the specified wire contains invalid gate connections.
    InvalidGate(usize),
    /// The specified output gate does not exist in the circuit.
    InvalidOutput(usize),
    /// The circuit does not specify any output gates.
    EmptyOutputs,
    /// The provided index does not correspond to any party.
    PartyIndexOutOfBounds,
}

impl Circuit {
    /// Returns all the wires (inputs + gates) in the circuit, in ascending order.
    pub fn wires(&self) -> Vec<Wire> {
        let mut gates = vec![];
        for (party, inputs) in self.input_gates.iter().enumerate() {
            for _ in 0..*inputs {
                gates.push(Wire::Input(party))
            }
        }
        for gate in self.gates.iter() {
            let gate = match gate {
                Gate::Xor(x, y) => Wire::Xor(*x, *y),
                Gate::And(x, y) => Wire::And(*x, *y),
                Gate::Not(x) => Wire::Not(*x),
            };
            gates.push(gate);
        }
        gates
    }

    /// Checks that the circuit only uses valid wires, includes no cycles, has outputs, etc.
    pub fn validate(&self) -> Result<(), CircuitError> {
        let wires = self.wires();
        for (i, g) in wires.iter().enumerate() {
            match g {
                Wire::Input(_) => {}
                &Wire::Xor(x, y) => {
                    if x >= i || y >= i {
                        return Err(CircuitError::InvalidGate(i));
                    }
                }
                &Wire::And(x, y) => {
                    if x >= i || y >= i {
                        return Err(CircuitError::InvalidGate(i));
                    }
                }
                &Wire::Not(x) => {
                    if x >= i {
                        return Err(CircuitError::InvalidGate(i));
                    }
                }
            }
        }
        if self.output_gates.is_empty() {
            return Err(CircuitError::EmptyOutputs);
        }
        for &o in self.output_gates.iter() {
            if o >= wires.len() {
                return Err(CircuitError::InvalidOutput(o));
            }
        }
        Ok(())
    }

    /// Evaluates the circuit with the specified inputs (with one `Vec<bool>` per party).
    ///
    /// Assumes that the inputs have been previously type-checked and **panics** if the number of
    /// parties or the bits of a particular party do not match the circuit.
    pub fn eval(&self, inputs: &[Vec<bool>]) -> Vec<bool> {
        let mut input_len = 0;
        for p in self.input_gates.iter() {
            input_len += p;
        }
        let mut output = vec![None; input_len + self.gates.len()];
        let inputs: Vec<_> = inputs.iter().map(|inputs| inputs.iter()).collect();
        let mut i = 0;
        if self.input_gates.len() != inputs.len() {
            panic!(
                "Circuit was built for {} parties, but found {} inputs",
                self.input_gates.len(),
                inputs.len()
            );
        }
        for (p, &input_gates) in self.input_gates.iter().enumerate() {
            if input_gates != inputs[p].len() {
                panic!(
                    "Expected {} input bits for party {}, but found {}",
                    input_gates,
                    p,
                    inputs[p].len()
                );
            }
            for bit in inputs[p].as_slice() {
                output[i] = Some(*bit);
                i += 1;
            }
        }
        for (w, gate) in self.gates.iter().enumerate() {
            let w = w + i;
            let output_bit = match gate {
                Gate::Xor(x, y) => output[*x].unwrap() ^ output[*y].unwrap(),
                Gate::And(x, y) => output[*x].unwrap() & output[*y].unwrap(),
                Gate::Not(x) => !output[*x].unwrap(),
            };
            output[w] = Some(output_bit);
        }

        let mut output_packed: Vec<bool> = Vec::with_capacity(self.output_gates.len());
        for output_gate in &self.output_gates {
            output_packed.push(output[*output_gate].unwrap());
        }
        output_packed
    }
}
