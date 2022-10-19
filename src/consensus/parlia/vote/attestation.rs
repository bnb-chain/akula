use crate::{
    consensus::{parlia::vote::ParliaVoteError, DuoError},
    crypto::keccak256,
    models::{BLSPublicKey, BLSSignature, BlockNumber, H256, KECCAK_LENGTH},
};
use bytes::{BufMut, Bytes, BytesMut};
use fastrlp::*;
use milagro_bls::{AmclError, PublicKey, Signature};
use serde::{Deserialize, Serialize};

/// max attestation extra length
pub const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;
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
        length_of_length(rlp_head.payload_length) + rlp_head.payload_length
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
            target_hash,
        })
    }
}

/// VoteEnvelope a signle vote from validator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteEnvelope {
    pub vote_address: BLSPublicKey,
    pub signature: BLSSignature,
    // the vote for fast finality
    pub data: VoteData,
}

impl Encodable for VoteEnvelope {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        Encodable::encode(&self.vote_address, out);
        Encodable::encode(&self.signature, out);
        Encodable::encode(&self.data, out);
    }

    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}

impl Decodable for VoteEnvelope {
    fn decode(buf: &mut &[u8]) -> Result<Self, DecodeError> {
        let rlp_head = Header::decode(buf)?;
        if !rlp_head.list {
            return Err(DecodeError::UnexpectedString);
        }
        let vote_address = Decodable::decode(buf)?;
        let signature = Decodable::decode(buf)?;
        let data = Decodable::decode(buf)?;

        Ok(Self {
            vote_address,
            signature,
            data,
        })
    }
}

impl VoteEnvelope {
    fn rlp_header(&self) -> Header {
        let mut rlp_head = Header {
            list: true,
            payload_length: 0,
        };

        rlp_head.payload_length += self.vote_address.length(); // vote_address
        rlp_head.payload_length += self.signature.length(); // signature
        rlp_head.payload_length += self.data.length(); // data

        rlp_head
    }

    /// hash, return VoteEnvelope's hash
    pub fn hash(&self) -> H256 {
        let mut out = BytesMut::new();
        Encodable::encode(self, &mut out);
        keccak256(&out[..])
    }

    /// verify, check if VoteEnvelope's signature is valid
    pub fn verify(&self) -> anyhow::Result<(), DuoError> {
        let bls_key = PublicKey::from_bytes(&self.vote_address[..])?;
        let sig = Signature::from_bytes(&self.signature[..])?;
        if !sig.verify(&self.data.hash()[..], &bls_key) {
            return Err(ParliaVoteError::InvalidVoteSig.into());
        }
        Ok(())
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
            extra,
        })
    }
}

impl Encodable for VoteAttestation {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_header().encode(out);
        Encodable::encode(&self.vote_address_set, out);
        Encodable::encode(&self.agg_signature, out);
        Encodable::encode(&self.data, out);
        Encodable::encode(&self.extra, out);
    }

    fn length(&self) -> usize {
        let rlp_head = self.rlp_header();
        length_of_length(rlp_head.payload_length) + rlp_head.payload_length
    }
}

impl VoteAttestation {
    fn rlp_header(&self) -> Header {
        let mut rlp_head = Header {
            list: true,
            payload_length: 0,
        };

        rlp_head.payload_length += self.vote_address_set.length(); // vote_address_set
        rlp_head.payload_length += self.agg_signature.length(); // agg_signature
        rlp_head.payload_length += self.data.length(); // data
        rlp_head.payload_length += self.extra.length(); // extra

        rlp_head
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{consensus::parlia::vote::signer::VoteSigner, models::BLSPrivateKey};
    use hex_literal::hex;

    #[test]
    fn check_attestation_decode() {
        let raw = hex::decode("f8ac01b860e7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cff84401a0be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce02a0169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719821234").unwrap();
        let mut buf = &*<Vec<u8> as Into<Bytes>>::into(raw.clone());
        let attestation: VoteAttestation = Decodable::decode(&mut buf).unwrap();
        assert_eq!(VoteAttestation {
            vote_address_set: 1,
            agg_signature: hex!("e7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cfe7eea193bc62f2c5a3e5e094f1edf9c1b7361c25f13939f848d7fef859b874cf").into(),
            data: VoteData {
                source_number: BlockNumber(1),
                source_hash: hex!("be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce").into(),
                target_number: BlockNumber(2),
                target_hash: hex!("169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719").into()
            },
            extra: hex::decode("1234").unwrap().into()
        }, attestation);

        let mut out: Vec<u8> = Vec::new();
        Encodable::encode(&attestation, &mut out);
        assert_eq!(out, raw);
    }

    #[test]
    fn check_vote_data_hash() {
        let vote_data = VoteData {
            source_number: BlockNumber(1),
            source_hash: hex!("be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce")
                .into(),
            target_number: BlockNumber(2),
            target_hash: hex!("169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719")
                .into(),
        };
        let expect: H256 =
            hex!("095db9c86230a3be933d197e5188d86d3d7107a09f8cd2b616e0cf253525aebc").into();
        assert_eq!(expect, vote_data.hash())
    }

    #[test]
    fn check_vote_envelope_hash() {
        let prv_key: BLSPrivateKey =
            hex!("493492773ec57b4e0c017f9c9430fed00f7efc1c11260516d24e5df9233f1e93").into();
        let pub_key: BLSPublicKey = hex!("ad152e3a168a9bba4b4681949810d891495a2d93c48cbae8878ee78cd5ff886b7ffed8f6794618a3be663a04339416e4").into();
        let signer = VoteSigner::new(prv_key, pub_key).unwrap();

        let vote = VoteData {
            source_number: BlockNumber(1),
            source_hash: hex!("be94fc6ce27f0f1f6d11141a0dd6bc01dba1c9c32be4162a2344c74b51b360ce")
                .into(),
            target_number: BlockNumber(2),
            target_hash: hex!("169ee5fc04a06e9bf377f671ffd176b81bc7b71799ff7d5cd4c9702944202719")
                .into(),
        };
        let ve = VoteEnvelope {
            vote_address: pub_key,
            signature: signer.sign(&vote),
            data: vote,
        };

        assert!(ve.verify().is_ok());
    }
}
