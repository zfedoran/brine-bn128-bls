use crate::errors::BLSError;

pub trait BLSSignature {
    fn to_bytes(&self) -> Result<[u8; 128], BLSError>;
}
