use fastrlp::*;
use fixed_hash::construct_fixed_hash;

/// length of BLS public key
pub const BLS_PUBLIC_KEY_LEN: usize = 48;
/// length of BLS private key
pub const BLS_PRIVATE_KEY_LEN: usize = 32;
/// length of BLS Signature key
pub const BLS_SIGNATURE_LEN: usize = 96;

construct_fixed_hash! {
    pub struct BLSPublicKey(BLS_PUBLIC_KEY_LEN);
}

construct_fixed_hash! {
    pub struct BLSPrivateKey(BLS_PRIVATE_KEY_LEN);
}

construct_fixed_hash! {
    pub struct BLSSignature(BLS_SIGNATURE_LEN);
}

mod serde {
    use super::*;
    use impl_serde::impl_fixed_hash_serde;

    impl_fixed_hash_serde!(BLSPublicKey, BLS_PUBLIC_KEY_LEN);
    impl_fixed_hash_serde!(BLSSignature, BLS_SIGNATURE_LEN);
}

impl Encodable for BLSPublicKey {
    fn encode(&self, out: &mut dyn BufMut) {
        Encodable::encode(&self.0, out);
    }

    fn length(&self) -> usize {
        self.0.length()
    }
}

impl Decodable for BLSPublicKey {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(Decodable::decode(buf)?))
    }
}

impl Encodable for BLSSignature {
    fn encode(&self, out: &mut dyn BufMut) {
        Encodable::encode(&self.0, out);
    }

    fn length(&self) -> usize {
        self.0.length()
    }
}

impl Decodable for BLSSignature {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        Ok(Self(Decodable::decode(buf)?))
    }
}
