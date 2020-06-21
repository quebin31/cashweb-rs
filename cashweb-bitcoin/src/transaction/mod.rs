pub mod input;
pub mod outpoint;
pub mod output;
pub mod script;

use std::fmt;

use bytes::{Buf, BufMut};

use crate::{
    var_int::{DecodeError as VarIntDecodeError, VarInt},
    Decodable, Encodable,
};
use input::{DecodeError as InputDecodeError, Input};
use output::{DecodeError as OutputDecodeError, Output};

/// Represents a transaction.
#[derive(Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub lock_time: u32,
}

impl Transaction {
    fn input_len_varint(&self) -> VarInt {
        VarInt(self.inputs.len() as u64)
    }

    fn output_len_varint(&self) -> VarInt {
        VarInt(self.outputs.len() as u64)
    }
}

impl Encodable for Transaction {
    #[inline]
    fn encoded_len(&self) -> usize {
        let input_length_varint_length = self.input_len_varint().encoded_len();
        let input_total_length: usize = self.inputs.iter().map(|input| input.encoded_len()).sum();
        let output_length_varint_length = VarInt(self.outputs.len() as u64).encoded_len();
        let output_total_length: usize = self.outputs.iter().map(|output| output.encoded_len()).sum();
        4 + input_length_varint_length
            + input_total_length
            + output_length_varint_length
            + output_total_length
            + 4
    }

    #[inline]
    fn encode_raw<B: BufMut>(&self, buf: &mut B) {
        buf.put_u32(self.version);
        self.input_len_varint().encode_raw(buf);
        for input in &self.inputs {
            input.encode_raw(buf);
        }
        self.output_len_varint().encode_raw(buf);
        for output in &self.outputs {
            output.encode_raw(buf);
        }
        buf.put_u32(self.lock_time);
    }
}

/// The error type associated with `Transaction` deserialization.
#[derive(Debug)]
pub enum DecodeError {
    VersionTooShort,
    InputCount(VarIntDecodeError),
    Input(InputDecodeError),
    OutputCount(VarIntDecodeError),
    Output(OutputDecodeError),
    LockTimeTooShort,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VersionTooShort => f.write_str("version too short"),
            Self::InputCount(err) => f.write_str(&format!("input count; {}", err)),
            Self::Input(err) => f.write_str(&format!("input; {}", err)),
            Self::OutputCount(err) => f.write_str(&format!("output count; {}", err)),
            Self::Output(err) => f.write_str(&format!("output; {}", err)),
            Self::LockTimeTooShort => f.write_str("lock time too short"),
        }
    }
}

impl Decodable for Transaction {
    type Error = DecodeError;

    fn decode<B: Buf>(mut buf: &mut B) -> Result<Self, Self::Error> {
        // Parse version
        if buf.remaining() < 4 {
            return Err(Self::Error::VersionTooShort);
        }
        let version = buf.get_u32();

        // Parse inputs
        let n_inputs: u64 = VarInt::decode(&mut buf)
            .map_err(Self::Error::InputCount)?
            .into();
        let inputs: Vec<Input> = (0..n_inputs)
            .map(|_| Input::decode(buf))
            .collect::<Result<Vec<Input>, _>>()
            .map_err(Self::Error::Input)?;

        // Parse outputs
        let n_outputs: u64 = VarInt::decode(&mut buf)
            .map_err(Self::Error::OutputCount)?
            .into();
        let outputs: Vec<Output> = (0..n_outputs)
            .map(|_| Output::decode(buf))
            .collect::<Result<Vec<Output>, _>>()
            .map_err(Self::Error::Output)?;

        // Parse lock time
        if buf.remaining() < 4 {
            return Err(Self::Error::LockTimeTooShort);
        }
        let lock_time = buf.get_u32();
        Ok(Transaction {
            version,
            lock_time,
            inputs,
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode() {
        let hex_tx = "0200000001dc0e0c39e2d7a7150ad058ab80b7b1d543097a785e4616fa59dcae8fbecce4240100000000ffffffff0120aa4400000000001976a914043ea5736aa3a48ebdd5034309b590505d8bdd9088ac00000000";
        let raw_tx = hex::decode(hex_tx).unwrap();
        Transaction::decode(&mut raw_tx.as_slice()).unwrap();
    }

    #[test]
    fn encode() {
        let hex_tx = "0200000001dc0e0c39e2d7a7150ad058ab80b7b1d543097a785e4616fa59dcae8fbecce4240100000000ffffffff0120aa4400000000001976a914043ea5736aa3a48ebdd5034309b590505d8bdd9088ac00000000";
        let raw_tx_input = hex::decode(hex_tx).unwrap();
        let tx = Transaction::decode(&mut raw_tx_input.as_slice()).unwrap();

        let buffer_len = tx.encoded_len();
        let mut raw_tx_output: Vec<u8> = Vec::with_capacity(buffer_len);
        tx.encode(&mut raw_tx_output).unwrap();
        assert_eq!(raw_tx_output, raw_tx_input)
    }

    #[test]
    fn encode_insufficent_capacity() {
        let hex_tx = "0200000001dc0e0c39e2d7a7150ad058ab80b7b1d543097a785e4616fa59dcae8fbecce4240100000000ffffffff0120aa4400000000001976a914043ea5736aa3a48ebdd5034309b590505d8bdd9088ac00000000";
        let raw_tx_input = hex::decode(hex_tx).unwrap();
        let tx = Transaction::decode(&mut raw_tx_input.as_slice()).unwrap();

        let mut raw_tx_output = Vec::with_capacity(0);
        assert!(tx.encode(&mut raw_tx_output.as_mut_slice()).is_err());
    }
}
