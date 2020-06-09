use std::fmt;

use bytes::Buf;

use super::{
    outpoint::{DecodeError as OutpointDecodeError, Outpoint},
    script::Script,
};
use crate::{
    var_int::{DecodeError as VarIntDecodeError, VarInt},
    Decodable,
};

/// The error type associated with `Input` deserialization.
#[derive(Debug)]
pub enum DecodeError {
    Outpoint(OutpointDecodeError),
    ScriptLen(VarIntDecodeError),
    ScriptTooShort,
    SequenceTooShort,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Outpoint(err) => f.write_str(&format!("outpoint; {}", err)),
            Self::ScriptLen(err) => f.write_str(&format!("script length; {}", err)),
            Self::ScriptTooShort => f.write_str("script too short"),
            Self::SequenceTooShort => f.write_str("sequence number too short"),
        }
    }
}

/// Represents an input.
#[derive(Debug)]
pub struct Input {
    pub outpoint: Outpoint,
    pub script: Script,
    pub sequence: u32,
}

impl Decodable for Input {
    type Error = DecodeError;

    fn decode<B: Buf>(mut buf: &mut B) -> Result<Self, Self::Error> {
        // Parse outpoint
        let outpoint = Outpoint::decode(&mut buf).map_err(Self::Error::Outpoint)?;

        // Parse script
        let script_len: u64 = VarInt::decode(&mut buf)
            .map_err(Self::Error::ScriptLen)?
            .into();
        let script_len = script_len as usize;
        if buf.remaining() < script_len {
            return Err(Self::Error::ScriptTooShort);
        }
        let mut raw_script = vec![0; script_len];
        buf.copy_to_slice(&mut raw_script);
        let script = raw_script.into();

        // Parse sequence number
        if buf.remaining() < 4 {
            return Err(Self::Error::SequenceTooShort);
        }
        let sequence = buf.get_u32();

        Ok(Input {
            outpoint,
            script,
            sequence,
        })
    }
}
