pub mod opcodes;

/// Represents a script.
#[derive(Debug)]
pub struct Script(Vec<u8>);

impl Into<Vec<u8>> for Script {
    fn into(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for Script {
    fn from(raw: Vec<u8>) -> Self {
        Script(raw)
    }
}

impl Script {
    /// Convert the script into the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.into()
    }

    /// Converts the script into a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Checks whether the script fits the OP_RETURN pattern.
    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == opcodes::OP_RETURN
    }

    /// Checks whether the scripts the P2PKH pattern.
    pub fn is_p2pkh(&self) -> bool {
        self.0.len() == 25
            && self.0[0] == opcodes::OP_DUP
            && self.0[1] == opcodes::OP_HASH160
            && self.0[2] == opcodes::OP_PUSHBYTES_20
            && self.0[23] == opcodes::OP_EQUALVERIFY
            && self.0[24] == opcodes::OP_CHECKSIG
    }
}
