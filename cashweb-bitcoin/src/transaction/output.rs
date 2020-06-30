//! This module contains the [`Output`] struct which represents a Bitcoin transaction output.
//! It enjoys [`Encodable`] and [`Decodable`].


use std::fmt;

use bytes::{Buf, BufMut};

use super::script::Script;
use crate::{
    var_int::{DecodeError as VarIntDecodeError, VarInt},
    Decodable, Encodable,
};

/// The error type associated with `Output` deserialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Value is too short.
    ValueTooShort,
    /// Unable to decode the script length variable-length integer.
    ScriptLen(VarIntDecodeError),
    /// Script is too short.
    ScriptTooShort,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ValueTooShort => f.write_str("value too short"),
            Self::ScriptLen(err) => f.write_str(&format!("script length: {}", err)),
            Self::ScriptTooShort => f.write_str("script too short"),
        }
    }
}

/// Represents an output.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Output {
    pub value: u64,
    pub script: Script,
}

impl Encodable for Output {
    #[inline]
    fn encoded_len(&self) -> usize {
        8 + self.script.len_varint().encoded_len() + self.script.encoded_len()
    }

    #[inline]
    fn encode_raw<B: BufMut>(&self, buf: &mut B) {
        buf.put_u64(self.value);
        self.script.len_varint().encode_raw(buf);
        self.script.encode_raw(buf);
    }
}

impl Decodable for Output {
    type Error = DecodeError;

    #[inline]
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
