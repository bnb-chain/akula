use crate::models::{
    BlockHeader, BlockNumber, ChainId, ChainSpec, Message, MessageSignature, YParityAndChainId,
};
use anyhow::anyhow;
use bytes::Bytes;
use ethereum_types::Address;
use parity_crypto::{publickey, publickey::KeyPair};
use primitive_types::H256;

#[derive(Clone, Debug)]
pub struct ECDSASigner {
    inner: KeyPair,
    chain_id: u64,
    /// Whether this signer should allow legacy transactions with malleability
    maleable: bool,
    /// Whether this signer should allow legacy transactions without chainId protection
    unprotected: bool,
    /// Whether this signer should allow transactions with replay protection via chainId
    protected: bool,
    /// Whether this signer should allow transactions with access list, superseeds protected
    access_list: bool,
    /// Whether this signer should allow transactions with basefee and tip (instead of gasprice), superseeds accesslist
    dynamic_fee: bool,
}

impl ECDSASigner {
    pub fn from_secret(secret: &[u8]) -> Self {
        ECDSASigner {
            inner: KeyPair::from_secret_slice(secret).unwrap(),
            chain_id: 0,
            maleable: false,
            unprotected: false,
            protected: false,
            access_list: false,
            dynamic_fee: false,
        }
    }
    pub fn from_chain_spec(
        signer: &ECDSASigner,
        chain_spec: &ChainSpec,
        block_number: BlockNumber,
    ) -> Self {
        let mut signer = ECDSASigner {
            inner: signer.inner.clone(),
            chain_id: 0,
            maleable: false,
            unprotected: true,
            protected: false,
            access_list: false,
            dynamic_fee: false,
        };

        if chain_spec.is_london(&block_number) {
            // All transaction types are still supported
            signer.protected = true;
            signer.access_list = true;
            signer.dynamic_fee = true;
            signer.chain_id = chain_spec.params.chain_id.0;
        } else if chain_spec.is_berlin(&block_number) {
            signer.protected = true;
            signer.access_list = true;
            signer.chain_id = chain_spec.params.chain_id.0;
        } else if chain_spec.is_spurious(&block_number) {
            signer.protected = true;
            signer.chain_id = chain_spec.params.chain_id.0;
        } else if chain_spec.is_homestead(&block_number) {
            // nothing
        } else {
            // Only allow malleable transactions in Frontier
            signer.maleable = true
        }
        signer
    }

    pub fn sign_tx(&self, msg: &Message) -> anyhow::Result<MessageSignature> {
        let sig = publickey::sign(
            self.inner.secret(),
            &publickey::Message::from_slice(&msg.hash()[..]),
        )?;
        let (r, s, v) = match msg {
            Message::Legacy { .. } => {
                let (r, s, mut v) = (sig.r(), sig.s(), sig.v() as u64);
                if self.chain_id == 0 {
                    v += 27;
                } else {
                    v += 35 + self.chain_id * 2;
                }
                (r, s, v)
            }
            Message::EIP2930 { chain_id, .. } => {
                if chain_id.0 != 0 && self.chain_id != chain_id.0 {
                    return Err(anyhow!(
                        "invalid EIP2930 tx, with wrong chain_id {}:{}",
                        chain_id.0,
                        self.chain_id
                    ));
                }
                (sig.r(), sig.s(), sig.v() as u64)
            }
            Message::EIP1559 { chain_id, .. } => {
                if chain_id.0 != 0 && self.chain_id != chain_id.0 {
                    return Err(anyhow!(
                        "invalid EIP1559 tx, with wrong chain_id {}:{}",
                        chain_id.0,
                        self.chain_id
                    ));
                }
                (sig.r(), sig.s(), sig.v() as u64)
            }
        };

        let yp =
            YParityAndChainId::from_v(v).ok_or_else(|| anyhow!("sign err: invalid signature v"))?;
        MessageSignature::new(yp.odd_y_parity, H256::from_slice(r), H256::from_slice(s))
            .ok_or_else(|| anyhow!("sign err: invalid signature"))
    }

    pub fn sign_block(&self, header: &BlockHeader, chain_id: ChainId) -> anyhow::Result<Bytes> {
        let sig = publickey::sign(
            self.inner.secret(),
            &publickey::Message::from_slice(header.hash_with_chain_id(chain_id.0).as_bytes()),
        )?;
        Ok(Bytes::copy_from_slice(sig.as_slice()))
    }

    pub fn addr(&self) -> Address {
        Address::from_slice(&self.inner.address()[..])
    }
}
