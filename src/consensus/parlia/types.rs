use primitive_types::H256;
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use fastrlp::{Decodable, DecodeError, Encodable, Header};
use crate::crypto::keccak256;
use crate::models::{BlockNumber, KECCAK_LENGTH};

/// length of BLS public key
pub const BLS_PUBLIC_KEY_LEN: usize = 48;
/// length of BLS Signature key
pub const BLS_SIGNATURE_LEN: usize = 96;
/// max attestation extra length
pub const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;

pub type BLSPublicKey = [u8; BLS_PUBLIC_KEY_LEN];
pub type BLSSignature = [u8; BLS_SIGNATURE_LEN];
pub type ValidatorsBitSet = u64;

/// VoteData represents the vote range that validator voted for fast finality.
#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize, Serialize)]
pub struct VoteData {
    /// The source block number should be the latest justified block number.
    pub source_number: BlockNumber,
    /// The block hash of the source block.
    pub source_hash: H256,
    /// The target block number which validator wants to vote for.
    pub target_number: BlockNumber,
    /// The block hash of the target block.
    pub target_hash: H256,
}

impl Encodable for VoteData {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        Encodable::encode(&self.source_number, out);
        Encodable::encode(&self.source_hash, out);
        Encodable::encode(&self.target_number, out);
        Encodable::encode(&self.target_hash, out);
    }

    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        fastrlp::length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}

impl VoteData {
    fn rlp_header(&self) -> Header {
        let mut rlp_head = Header {
            list: true,
            payload_length: 0,
        };

        rlp_head.payload_length += self.source_number.length(); // source_number
        rlp_head.payload_length += KECCAK_LENGTH + 1; // source_hash
        rlp_head.payload_length += self.target_number.length(); // target_number
        rlp_head.payload_length += KECCAK_LENGTH + 1; // target_hash

        rlp_head
    }

    pub(crate) fn hash(&self) -> H256 {
        let mut out = BytesMut::new();
        Encodable::encode(self, &mut out);
        keccak256(&out[..])
    }
}

impl Decodable for VoteData {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        let rlp_head = Header::decode(buf)?;
        if !rlp_head.list {
            return Err(DecodeError::UnexpectedString);
        }
        let source_number = Decodable::decode(buf)?;
        let source_hash = Decodable::decode(buf)?;
        let target_number = Decodable::decode(buf)?;
        let target_hash = Decodable::decode(buf)?;

        Ok(Self {
            source_number,
            source_hash,
            target_number,
            target_hash
        })
    }
}

/// VoteAttestation represents the votes of super majority validators.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteAttestation {
    /// The bitset marks the voted validators.
    pub vote_address_set: ValidatorsBitSet,
    /// The aggregated BLS signature of the voted validators' signatures.
    pub agg_signature: BLSSignature,
    /// The vote data for fast finality.
    pub data: VoteData,
    /// Reserved for future usage.
    pub extra: Bytes,
}

impl Decodable for VoteAttestation {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        let rlp_head = Header::decode(buf)?;
        if !rlp_head.list {
            return Err(DecodeError::UnexpectedString);
        }
        let vote_address_set = Decodable::decode(buf)?;
        let agg_signature = Decodable::decode(buf)?;
        let data = Decodable::decode(buf)?;
        let extra = Decodable::decode(buf)?;

        Ok(Self {
            vote_address_set,
            agg_signature,
            data,
            extra
        })
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
    fn check_attestation_decode() {
        let mut buf = &*<Vec<u8> as Into<Bytes>>::into(hex::decode("f8ac01b860e7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cff84401a0be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce02a0169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719821234").unwrap());
        let attestation: VoteAttestation = Decodable::decode(&mut buf).unwrap();
        assert_eq!(VoteAttestation {
            vote_address_set: 1,
            agg_signature: hex!("e7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cf"),
            data: VoteData {
                source_number: BlockNumber(1),
                source_hash: hex!("be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce").into(),
                target_number: BlockNumber(2),
                target_hash: hex!("169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719").into()
            },
            extra: hex::decode("1234").unwrap().into()
        }, attestation)
    }

    #[test]
    fn check_vote_data_hash() {
        let vote_data = VoteData {
            source_number: BlockNumber(1),
            source_hash: hex!("be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce").into(),
            target_number: BlockNumber(2),
            target_hash: hex!("169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719").into()
        };
        let expect: H256 = hex!("095db9c86230a3be933d197e5188d86d3d7107a09f8cd2b616e0cf253525aebc").into();
        assert_eq!(expect, vote_data.hash())
    }
}