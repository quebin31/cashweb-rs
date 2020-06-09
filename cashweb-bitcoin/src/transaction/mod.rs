pub mod input;
pub mod outpoint;
pub mod output;
pub mod script;

use std::fmt;

use bytes::Buf;

use crate::{
    var_int::{DecodeError as VarIntDecodeError, VarInt},
    Decodable,
};
use input::{DecodeError as InputDecodeError, Input};
use output::{DecodeError as OutputDecodeError, Output};

/// Represents a transaction.
#[derive(Debug)]
pub struct Transaction {
    pub version: u32,
    pub lock_time: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
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
        let tx = Transaction::decode(&mut raw_tx.as_slice()).unwrap();
    }
}
