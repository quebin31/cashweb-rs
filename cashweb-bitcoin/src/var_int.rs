use std::fmt;

use bytes::Buf;

use super::Decodable;

/// The error type associated with `VarInt` deserialization.
#[derive(Debug)]
pub enum DecodeError {
    TooShort,
    NonMinimal,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => f.write_str("varint too short"),
            Self::NonMinimal => f.write_str("varint non-minimal"),
        }
    }
}

/// Represents a variable-length integer.
pub struct VarInt(u64);

impl Into<u64> for VarInt {
    fn into(self) -> u64 {
        self.0
    }
}

impl Decodable for VarInt {
    type Error = DecodeError;

    /// Parse variable-length integer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error> {
        if !buf.has_remaining() {
            return Err(Self::Error::TooShort);
        }
        let first_byte = buf.get_u8();
        match first_byte {
            0xff => {
                if buf.remaining() < 8 {
                    return Err(Self::Error::TooShort);
                }
                let x = buf.get_u64();
                if x < 0x100000000 {
                    Err(Self::Error::NonMinimal)
                } else {
                    Ok(Self(x))
                }
            }
            0xfe => {
                if buf.remaining() < 4 {
                    return Err(Self::Error::TooShort);
                }
                let x = buf.get_uint(4);
                if x < 0x10000 {
                    Err(Self::Error::NonMinimal)
                } else {
                    Ok(Self(x))
                }
            }
            0xfd => {
                if buf.remaining() < 2 {
                    return Err(Self::Error::TooShort);
                }
                let x = buf.get_uint(2);
                if x < 0xFD {
                    Err(Self::Error::NonMinimal)
                } else {
                    Ok(Self(x))
                }
            }
            n => Ok(VarInt(n.into())),
        }
    }
}
