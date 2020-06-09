pub mod prelude;
pub mod transaction;
pub mod var_int;

use bytes::Buf;

pub trait Decodable: Sized {
    type Error;

    fn decode<B: Buf>(buf: &mut B) -> Result<Self, Self::Error>;
}
