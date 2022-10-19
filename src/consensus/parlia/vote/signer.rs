use super::*;
use crate::{
    consensus::DuoError,
    models::{BLSPrivateKey, BLSPublicKey, BLSSignature},
};
use milagro_bls::{AmclError, PublicKey, SecretKey, Signature};

#[derive(Clone, Debug)]
pub struct VoteSigner {
    secret_key: SecretKey,
    pub_key: PublicKey,
}

impl VoteSigner {
    /// new, init VoteSigner from keys.
    pub fn new(prv_key: BLSPrivateKey, public_key: BLSPublicKey) -> anyhow::Result<Self, DuoError> {
        let secret_key = SecretKey::from_bytes(&prv_key[..])?;
        let pub_key = PublicKey::from_bytes(&public_key[..])?;
        Ok(VoteSigner {
            secret_key,
            pub_key,
        })
    }

    /// sign, sign vote as bls signature
    pub fn sign(&self, vote: &VoteData) -> BLSSignature {
        let sig = Signature::new(&vote.hash()[..], &self.secret_key);
        BLSSignature(sig.as_bytes())
    }

    /// sign, sign vote as bls signature
    pub fn addr(&self) -> BLSPublicKey {
        BLSPublicKey(self.pub_key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::BlockNumber;
    use hex_literal::hex;

    #[test]
    fn vote_signer_sign() {
        let prv_key: BLSPrivateKey =
            hex!("493492773ec57b4e0c017f9c9430fed00f7efc1c11260516d24e5df9233f1e93").into();
        let pub_key: BLSPublicKey = hex!("ad152e3a168a9bba4b4681949810d891495a2d93c48cbae8878ee78cd5ff886b7ffed8f6794618a3be663a04339416e4").into();
        let signer = VoteSigner::new(prv_key, pub_key).unwrap();

        let vote = VoteData {
            source_number: BlockNumber(1),
            source_hash: hex!("9b921b6ee679b3c8fc5595e07ae6b059d9a71e7d2ef2ea44eabe76963cd1ac75")
                .into(),
            target_number: BlockNumber(2),
            target_hash: hex!("c6c86a487c396dec1fdddeaa19b502ddc34dd4973de8d78fe91d8237f40477a2")
                .into(),
        };
        let sig = signer.sign(&vote);
        let bls_sig = Signature::from_bytes(&sig[..]).unwrap();
        assert_eq!(true, bls_sig.verify(&vote.hash()[..], &signer.pub_key));
    }
}
