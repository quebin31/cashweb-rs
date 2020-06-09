pub mod prelude;
pub mod transaction;
pub mod var_int;

use bytes::Buf;

/// Provides a common interface for the deserialization of bitcoin structures.
pub trait Decodable: Sized {
    type Error;

    /// Decode a buffer.
    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>;
}
