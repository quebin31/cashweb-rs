use std::fmt;

use bytes::Buf;

use crate::Decodable;

/// Represents an outpoint.
#[derive(Debug)]
pub struct Outpoint {
    pub tx_id: [u8; 32],
    pub vout: u32,
}

/// The error type associated with `Outpoint` deserialization.
#[derive(Debug)]
pub struct DecodeError;

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("outpoint too short")
    }
}

impl Decodable for Outpoint {
    type Error = DecodeError;

    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
        if buf.remaining() < 32 + 4 {
            return Err(DecodeError);
        }
        let mut tx_id = [0; 32];
        buf.copy_to_slice(&mut tx_id);
        let vout = buf.get_u32();

        Ok(Outpoint { tx_id, vout })
    }
}
