use std::fmt;

use bytes::{Buf, BufMut};

use super::{Decodable, Encodable};

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
#[derive(Debug, PartialEq)]
pub struct VarInt(pub u64);

impl Into<u64> for VarInt {
    fn into(self) -> u64 {
        self.0
    }
}

impl Encodable for VarInt {
    #[inline]
    fn encoded_len(&self) -> usize {
        match self.0 {
            0..=0xfc => 1,
            0xfd..=0xffff => 3,
            0x10000..=0xffffffff => 5,
            _ => 9,
        }
    }

    fn encode_raw<B: BufMut>(&self, buf: &mut B) {
        match self.0 {
            0..=0xfc => {
                buf.put_uint(self.0, 1);
            }
            0xfd..=0xffff => {
                buf.put_u8(0xfd);
                buf.put_uint(self.0, 2);
            }
            0x10000..=0xffffffff => {
                buf.put_u8(0xfe);
                buf.put_uint(self.0, 4);
            }
            _ => {
                buf.put_u8(0xff);
                buf.put_u64(self.0);
            }
        }
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
                if x < 0xfd {
                    Err(Self::Error::NonMinimal)
                } else {
                    Ok(Self(x))
                }
            }
            n => Ok(VarInt(n.into())),
        }
    }
}
