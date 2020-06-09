use std::fmt;

use bytes::Buf;

use super::script::Script;
use crate::{
    var_int::{DecodeError as VarIntDecodeError, VarInt},
    Decodable,
};

#[derive(Debug)]
pub enum DecodeError {
    ValueTooShort,
    ScriptLen(VarIntDecodeError),
    ScriptTooShort,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooShort => f.write_str("value too short"),
            Self::ScriptLen(err) => f.write_str(&format!("script length; {}", err)),
            Self::ScriptTooShort => f.write_str("script too short"),
        }
    }
}

/// Represents an output.
#[derive(Debug)]
pub struct Output {
    pub value: u64,
    pub script: Script,
}

impl Decodable for Output {
    type Error = DecodeError;

    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
        // Get value
        if buf.remaining() < 8 {
            return Err(Self::Error::ValueTooShort);
        }
        let value = buf.get_u64();

        // Get script
        let script_len: u64 = VarInt::decode(buf).map_err(Self::Error::ScriptLen)?.into();
        let script_len = script_len as usize;
        if buf.remaining() < script_len {
            return Err(Self::Error::ScriptTooShort);
        }
        let mut raw_script = vec![0; script_len];
        buf.copy_to_slice(&mut raw_script);
        let script = raw_script.into();
        Ok(Output { value, script })
    }
}
