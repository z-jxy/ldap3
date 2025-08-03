#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtlmHash(NtlmHashBytes);

pub type NtlmHashBytes = [u8; 16];

impl NtlmHash {
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl TryFrom<&[u8]> for NtlmHash {
    type Error = &'static str;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        if value.len() != 16 {
            return Err("NTLM hash must be exactly 16 bytes");
        }

        let mut hash = [0u8; 16];
        hash.copy_from_slice(value);
        Ok(NtlmHash(hash))
    }
}

impl From<NtlmHash> for [u8; 16] {
    fn from(hash: NtlmHash) -> Self {
        hash.0
    }
}

impl TryFrom<&str> for NtlmHash {
    type Error = &'static str;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        if value.len() != 32 {
            return Err("NTLM hash must be a 32-character hex string");
        }
        let bytes = hex::decode(value).map_err(|_| "Invalid hex string")?;
        debug_assert!(bytes.len() == 16);
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&bytes);

        Ok(NtlmHash(hash))
    }
}

impl AsRef<NtlmHash> for NtlmHash {
    fn as_ref(&self) -> &NtlmHash {
        self
    }
}
