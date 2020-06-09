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
    pub fn into_bytes(self) -> Vec<u8> {
        self.into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn is_op_return(&self) -> bool {
        !self.0.is_empty() && self.0[0] == opcodes::OP_RETURN
    }
}
