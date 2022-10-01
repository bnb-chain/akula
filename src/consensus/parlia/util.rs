use crate::{
    consensus::parlia::{snapshot::ValidatorInfo, *},
    crypto,
};
use ethereum_types::{Address, Public, H256};
use fastrlp::Decodable;
use lazy_static::lazy_static;
use secp256k1::{
    ecdsa::{RecoverableSignature, RecoveryId},
    Message as SecpMessage, SECP256K1,
};
use sha3::{Digest, Keccak256};
use std::{collections::HashSet, str::FromStr};

/// How many cache with recovered signatures.
const RECOVERED_CREATOR_CACHE_NUM: usize = 4096;

lazy_static! {

    /// recovered creator cache map by block_number: creator_address
    static ref RECOVERED_CREATOR_CACHE: RwLock<LruCache<H256, Address>> = RwLock::new(LruCache::new(RECOVERED_CREATOR_CACHE_NUM));

    pub static ref SYSTEM_ACCOUNT: Address = Address::from_str("ffffFFFfFFffffffffffffffFfFFFfffFFFfFFfE").unwrap();
    pub static ref VALIDATOR_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001000").unwrap();
    pub static ref SLASH_CONTRACT: Address =  Address::from_str("0000000000000000000000000000000000001001").unwrap();
    pub static ref SYSTEM_REWARD_CONTRACT: Address = Address::from_str("0000000000000000000000000000000000001002").unwrap();
    pub static ref SYSTEM_CONTRACTS: HashSet<Address> = [
        "0000000000000000000000000000000000001000",
        "0000000000000000000000000000000000001001",
        "0000000000000000000000000000000000001002",
        "0000000000000000000000000000000000001003",
        "0000000000000000000000000000000000001004",
        "0000000000000000000000000000000000001005",
        "0000000000000000000000000000000000001006",
        "0000000000000000000000000000000000001007",
        "0000000000000000000000000000000000001008",
        "0000000000000000000000000000000000002000",
    ]
    .iter()
    .map(|x| Address::from_str(x).unwrap())
    .collect();
}

pub struct Signature([u8; 65]);

pub fn public_to_address(public: &Public) -> Address {
    let hash = crypto::keccak256(public);
    Address::from_slice(&hash[12..])
}

/// whether the contract is system or not
pub fn is_invoke_system_contract(addr: &Address) -> bool {
    SYSTEM_CONTRACTS.contains(addr)
}

/// whether the transaction is system or not
pub fn is_system_transaction(tx: &Message, sender: &Address, author: &Address) -> bool {
    if let TransactionAction::Call(to) = tx.action() {
        *sender == *author && is_invoke_system_contract(&to) && tx.max_fee_per_gas() == 0
    } else {
        false
    }
}

/// parse_validators from bytes
pub fn parse_epoch_validators(bytes: &[u8]) -> Result<Vec<Address>, DuoError> {
    if bytes.len() % EXTRA_VALIDATOR_LEN != 0 {
        return Err(ParliaError::WrongHeaderExtraSignersLen {
            expected: 0,
            got: bytes.len() % EXTRA_VALIDATOR_LEN,
            msg: format!("signers bytes len not correct!"),
        }
        .into());
    }
    let n = bytes.len() / ADDRESS_LENGTH;
    let mut res = BTreeSet::new();
    for i in 0..n {
        let address = Address::from_slice(&bytes[(i * ADDRESS_LENGTH)..((i + 1) * ADDRESS_LENGTH)]);
        res.insert(address);
    }
    Ok(res.into_iter().collect())
}

/// Recover parlia block creator from signature
pub fn recover_creator(header: &BlockHeader, chain_id: ChainId) -> Result<Address, DuoError> {
    // Initialization
    let mut cache = RECOVERED_CREATOR_CACHE.write();
    if let Some(creator) = cache.get_mut(&header.hash()) {
        return Ok(*creator);
    }

    let extra_data = &header.extra_data;

    if extra_data.len() < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
        return Err(ParliaError::WrongHeaderExtraLen {
            expected: EXTRA_VANITY_LEN + EXTRA_SEAL_LEN,
            got: extra_data.len(),
        }
        .into());
    }
    let signature_offset = header.extra_data.len() - EXTRA_SEAL_LEN;

    let sig = &header.extra_data[signature_offset..signature_offset + 64];
    let rec = RecoveryId::from_i32(header.extra_data[signature_offset + 64] as i32)?;
    let signature = RecoverableSignature::from_compact(sig, rec)?;

    let mut sig_hash_header = header.clone();
    sig_hash_header.extra_data = Bytes::copy_from_slice(&header.extra_data[..signature_offset]);
    let message =
        &SecpMessage::from_slice(sig_hash_header.hash_with_chain_id(chain_id.0).as_bytes())?;

    let public = &SECP256K1.recover_ecdsa(message, &signature)?;
    let address_slice = &Keccak256::digest(&public.serialize_uncompressed()[1..])[12..];

    let creator = Address::from_slice(address_slice);
    cache.insert(header.hash(), creator.clone());
    Ok(creator)
}

/// check tx is similar
pub fn is_similar_tx(actual: &Message, expect: &Message) -> bool {
    if actual.max_fee_per_gas() == expect.max_fee_per_gas()
        && actual.max_fee_per_gas() == expect.max_fee_per_gas()
        && actual.value() == expect.value()
        && actual.input() == expect.input()
        && actual.action() == expect.action()
    {
        true
    } else {
        false
    }
}

/// find header.block_number - count, block header
pub fn find_ancient_header(
    header_reader: &dyn HeaderReader,
    header: &BlockHeader,
    count: u64,
) -> Result<BlockHeader, DuoError> {
    let mut result = header.clone();
    for _ in 0..count {
        result = header_reader.read_parent_header(&result)?.ok_or_else(|| {
            ParliaError::UnknownHeader {
                number: result.number,
                hash: result.hash(),
            }
        })?;
    }
    Ok(result)
}

// verify_extra_len check header's extra length if valid
pub fn verify_extra_len(
    header: &BlockHeader,
    chain_spec: &ChainSpec,
    epoch: u64,
) -> Result<(), DuoError> {
    let extra_len = header.extra_data.len();
    if extra_len < EXTRA_VANITY_LEN + EXTRA_SEAL_LEN {
        return Err(ParliaError::WrongHeaderExtraLen {
            expected: EXTRA_VANITY_LEN + EXTRA_SEAL_LEN,
            got: extra_len,
        }
        .into());
    }

    if header.number.0 % epoch != 0 {
        return Ok(());
    }

    // check if has correct some address in epoch chg, before boneh
    if !chain_spec.is_boneh(&header.number) {
        if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) / EXTRA_VALIDATOR_LEN == 0 {
            return Err(ParliaError::WrongHeaderExtraSignersLen {
                expected: EXTRA_VANITY_LEN + EXTRA_SEAL_LEN + EXTRA_VALIDATOR_LEN,
                got: extra_len,
                msg: format!("signers empty in epoch change before boneh!"),
            }
            .into());
        }
        if (extra_len - EXTRA_SEAL_LEN - EXTRA_VANITY_LEN) % EXTRA_VALIDATOR_LEN != 0 {
            return Err(ParliaError::WrongHeaderExtraSignersLen {
                expected: EXTRA_VANITY_LEN + EXTRA_SEAL_LEN,
                got: extra_len,
                msg: format!("signers not correct in epoch change before boneh!"),
            }
            .into());
        }

        return Ok(());
    }

    // check if has correct BLS keys in epoch chg, after boneh
    let count = header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] as usize;
    let expect =
        EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH + EXTRA_SEAL_LEN + count * EXTRA_VALIDATOR_LEN_IN_BONEH;
    if count == 0 || extra_len < expect {
        return Err(ParliaError::WrongHeaderExtraSignersLen {
            expected: expect,
            got: extra_len,
            msg: format!(
                "signers not correct in epoch change after boneh!, count: {}",
                count
            ),
        }
        .into());
    }

    Ok(())
}

/// get_validator_bytes_from_header returns the validators bytes extracted from the header's extra field if exists.
///
/// The validators bytes would be contained only in the epoch block's header, and its each validator bytes length is fixed.
///
/// On boneh fork, we introduce vote attestation into the header's extra field, so extra format is different from before.
///
/// Validators Bytes not empty in epoch block, Vote Attestation may not empty in justified block.
///
/// Before boneh fork: |---Extra Vanity---|---Validators Bytes (or Empty)---|---Extra Seal---|
///
/// Validators Number and Validators Bytes not empty in epoch block, Vote Attestation may not empty in justified block.
///
/// After boneh fork:  |---Extra Vanity---|---Validators Number(or Empty)---|---Validators Bytes (or Empty)---|---Vote Attestation (or Empty)---|---Extra Seal---|
pub fn get_validator_bytes_from_header<'a, 'b>(
    header: &'a BlockHeader,
    chain_spec: &'b ChainSpec,
    epoch: u64,
) -> anyhow::Result<&'a [u8]> {
    verify_extra_len(header, chain_spec, epoch)?;

    if header.number.0 % epoch != 0 {
        return Err(ParliaError::NotInEpoch {
            block: header.number,
            err: format!("get_validator_bytes_from_header but not in epoch block!"),
        }
        .into());
    }
    let extra_len = header.extra_data.len();

    if !chain_spec.is_boneh(&header.number) {
        return Ok(&header.extra_data[EXTRA_VANITY_LEN..extra_len - EXTRA_SEAL_LEN]);
    }

    let count = header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] as usize;
    let start = EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH;
    let end = start + count * EXTRA_VALIDATOR_LEN_IN_BONEH;

    return Ok(&header.extra_data[start..end]);
}

/// get_validator_len_from_header returns the validators len
pub fn get_validator_len_from_header(
    header: &BlockHeader,
    chain_spec: &ChainSpec,
    epoch: u64,
) -> anyhow::Result<usize> {
    verify_extra_len(header, chain_spec, epoch)?;
    let extra_len = header.extra_data.len();

    if !chain_spec.is_boneh(&header.number) {
        return Ok(extra_len - EXTRA_VANITY_LEN - EXTRA_SEAL_LEN);
    }

    if header.number.0 % epoch != 0 {
        return Ok(0);
    }

    // after boneh, when epoch header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] is validator size.
    let count = header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] as usize;
    return Ok(count * EXTRA_VALIDATOR_LEN_IN_BONEH);
}

pub fn parse_validators_from_header(
    header: &BlockHeader,
    chain_spec: &ChainSpec,
    epoch: u64,
) -> anyhow::Result<(Vec<Address>, Option<HashMap<Address, ValidatorInfo>>)> {
    let val_bytes = get_validator_bytes_from_header(header, chain_spec, epoch)?;

    if !chain_spec.is_boneh(&header.number) {
        let count = val_bytes.len() / EXTRA_VALIDATOR_LEN;
        let mut vals = Vec::with_capacity(count);
        for i in 0..count {
            let start = i * EXTRA_VALIDATOR_LEN;
            let end = start + EXTRA_VALIDATOR_LEN;
            vals.push(Address::from_slice(&val_bytes[start..end]));
        }

        return Ok((vals, None));
    }

    let count = val_bytes.len() / EXTRA_VALIDATOR_LEN_IN_BONEH;
    let mut vals = Vec::with_capacity(count);
    let mut val_info_map = HashMap::with_capacity(count);
    for i in 0..count {
        let start = i * EXTRA_VALIDATOR_LEN_IN_BONEH;
        let end = start + EXTRA_VALIDATOR_LEN;
        let addr = Address::from_slice(&val_bytes[start..end]);
        vals.push(addr);

        let start = i * EXTRA_VALIDATOR_LEN_IN_BONEH + EXTRA_VALIDATOR_LEN;
        let end = i * EXTRA_VALIDATOR_LEN_IN_BONEH + EXTRA_VALIDATOR_LEN_IN_BONEH;
        val_info_map.insert(
            addr,
            ValidatorInfo {
                index: i + 1,
                vote_addr: BLSPublicKey::from_slice(&val_bytes[start..end]),
            },
        );
    }

    return Ok((vals, Some(val_info_map)));
}

/// get_vote_attestation returns the vote attestation from the header's extra field
pub fn get_vote_attestation_from_header(
    header: &BlockHeader,
    chain_spec: &ChainSpec,
    epoch: u64,
) -> Result<Option<VoteAttestation>, DuoError> {
    verify_extra_len(header, chain_spec, epoch)?;

    let mut raw;
    let extra_len = header.extra_data.len();
    if header.number.0 % epoch != 0 {
        raw = &header.extra_data[EXTRA_VANITY_LEN..extra_len - EXTRA_SEAL_LEN]
    } else {
        let count = header.extra_data[EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH - 1] as usize;
        let start = EXTRA_VANITY_LEN_WITH_NUM_IN_BONEH + count * EXTRA_VALIDATOR_LEN_IN_BONEH;
        let end = extra_len - EXTRA_SEAL_LEN;
        raw = &header.extra_data[start..end];
    }
    if raw.len() == 0 {
        return Ok(None);
    }

    Ok(Some(Decodable::decode(&mut raw)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitset::BitSet;
    use ethnum::u256;
    use hex_literal::hex;

    #[test]
    fn test_bsc_creator_recover() {
        let header = &BlockHeader{
            parent_hash: hex!("0d21840abff46b96c84b2ac9e10e4f5cdaeb5693cb665db62a2f3b02d2d57b5b").into(),
            ommers_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
            beneficiary: hex!("2a7cdd959bfe8d9487b2a43b33565295a698f7e2").into(),
            state_root: hex!("1db428ea79cb2e8cc233ae7f4db7c3567adfcb699af668a9f583fdae98e95588").into(),
            transactions_root: hex!("53a8743b873570daa630948b1858eaf5dc9bb0bca2093a197e507b2466c110a0").into(),
            receipts_root: hex!("fc7c0fda97e67ed8ae06e7a160218b3df995560dfcb209a3b0dddde969ec6b00").into(),
            logs_bloom: hex!("08000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000").into(),
            difficulty: u256::new(2),
            number: BlockNumber(1),
            gas_limit: 39843751 as u64,
            gas_used: 3148599 as u64,
            timestamp: 1598671449 as u64,
            extra_data: hex::decode("d883010002846765746888676f312e31332e34856c696e757800000000000000924cd67a1565fdd24dd59327a298f1d702d6b7a721440c063713cecb7229f4e162ae38be78f6f71aa5badeaaef35cea25061ee2100622a4a1631a07e862b517401").unwrap().into(),
            mix_hash: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            nonce: hex!("0000000000000000").into(),
            base_fee_per_gas: None
        };
        info!("test header {}:{}", header.number.0, header.hash());
        assert_eq!(
            header.hash(),
            hex!("04055304e432294a65ff31069c4d3092ff8b58f009cdb50eba5351e0332ad0f6").into()
        );
        let addr = recover_creator(header, ChainId(56_u64)).unwrap();
        assert_eq!(
            addr,
            Address::from_str("2a7cdd959bfe8d9487b2a43b33565295a698f7e2").unwrap()
        );
    }

    #[test]
    fn test_bsc_creator_recover_with_base_fee() {
        let header = &BlockHeader{
            parent_hash: hex!("40857a8493d09dbbd90ec1652b76d08895b6619cc4bec4f7b271a5711bbe43ce").into(),
            ommers_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
            beneficiary: hex!("68bcc47e7986bc68cb0bfa98e2be61a3f7b13457").into(),
            state_root: hex!("450d60b65a4404ac4be9261a0b084f6f7b050d474433d8d8d5da28ec50a17743").into(),
            transactions_root: hex!("56d0b0e345685373a31b51afb62deb5cdf866969b11351c6fd3474c42837dadf").into(),
            receipts_root: hex!("8a0c9a49afb03778767f4f075bc650a6ddcae5aa3d62332abe02a85699f4bbbc").into(),
            logs_bloom: hex!("08000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000300000000000000000000000000000").into(),
            difficulty: u256::new(2),
            number: BlockNumber(1),
            gas_limit: 39960939 as u64,
            gas_used: 1507580 as u64,
            timestamp: 1665284133 as u64,
            extra_data: hex::decode("d98301010b846765746888676f312e31382e348664617277696e00004a9b5e4dfd87cf956e4a3707e3af971d393717f76e8b61208f00dafe34f378b6e7a6950513f40e32ebb26998f9d92e441b3e5fcbc131205669b6de522b51b50846c18a9301").unwrap().into(),
            mix_hash: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            nonce: hex!("0000000000000000").into(),
            base_fee_per_gas: Some(u256::new(875000000_u128))
        };
        info!("test header {}:{}", header.number.0, header.hash());
        assert_eq!(
            header.hash(),
            hex!("2ffb6bfbd956678a4c13a8b7280c108df1554880adda7ef08eb15b61813bb45b").into()
        );
        let addr = recover_creator(header, ChainId(714_u64)).unwrap();
        assert_eq!(
            addr,
            Address::from_str("68bcc47e7986bc68cb0bfa98e2be61a3f7b13457").unwrap()
        );
    }

    #[test]
    fn test_parse_validators() {
        let header = BlockHeader {
            number: BlockNumber(0),
            extra_data: Bytes::from(<Vec<u8> as Into<Vec<u8>>>::into(hex!("00000000000000000000000000000000000000000000000000000000000000000568bcc47e7986bc68cb0bfa98e2be61a3f7b1345785e6972fc98cd3c81d64d40e325acfed44365b97a7567a27939c14dbc7512ddcf54cb1284eb637cfa308ae4e00cb55886baea1fb85b000bfe00edc273220f5e020f1088c8addebd6ef7609df215e006987040d0a643858f3a4d791beaa77177d67529160e645fac54f0d8acdcd5a088393cb6681d179e4f1ffeb30abf200c181ab83f917a1d4266889abcc45efe76bec679ca35c27adbd66fb9712a278e3c8530ab25cfaf997765aee574f5c5745dbb873dbf7e961684347a23ea8933ea51431247bbe5778ed8d16f75c7e1da1484f2b97137fb957daad064ca6cbe5b99549249ceb51f42e928ec091f94fed642ddffe3a9916769538decd0a9937bf0485c4d37ee8751e062b6ef6e211569b09488b198b20e24ad933b9af0a55a6d34a08e10b832a10f389154dc0dec79b63a38b79ea2f0d9f4fa664b3c06b1b2437cb58236f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").into())),
            ..Default::default()
        };
        let chain_spec = mock_chain_sepc();
        let (vals, val_info_map) = parse_validators_from_header(&header, &chain_spec, 200).unwrap();
        let val_info_map = val_info_map.unwrap();
        assert_eq!(
            vec![
                <Address as Into<Address>>::into(
                    hex!("68bcc47e7986bc68cb0bfa98e2be61a3f7b13457").into()
                ),
                hex!("6baea1fb85b000bfe00edc273220f5e020f1088c").into(),
                hex!("d179e4f1ffeb30abf200c181ab83f917a1d42668").into(),
                hex!("a23ea8933ea51431247bbe5778ed8d16f75c7e1d").into(),
                hex!("0485c4d37ee8751e062b6ef6e211569b09488b19").into(),
            ],
            vals
        );

        let bls_keys: Vec<BLSPublicKey> = vals
            .iter()
            .map(|x| val_info_map.get(x).unwrap().vote_addr)
            .collect();
        assert_eq!(vec![
            <BLSPublicKey as Into<BLSPublicKey>>::into(hex!("85e6972fc98cd3c81d64d40e325acfed44365b97a7567a27939c14dbc7512ddcf54cb1284eb637cfa308ae4e00cb5588").into()),
            hex!("8addebd6ef7609df215e006987040d0a643858f3a4d791beaa77177d67529160e645fac54f0d8acdcd5a088393cb6681").into(),
            hex!("89abcc45efe76bec679ca35c27adbd66fb9712a278e3c8530ab25cfaf997765aee574f5c5745dbb873dbf7e961684347").into(),
            hex!("a1484f2b97137fb957daad064ca6cbe5b99549249ceb51f42e928ec091f94fed642ddffe3a9916769538decd0a9937bf").into(),
            hex!("8b20e24ad933b9af0a55a6d34a08e10b832a10f389154dc0dec79b63a38b79ea2f0d9f4fa664b3c06b1b2437cb58236f").into(),
        ], bls_keys);
    }

    #[test]
    fn test_parse_attestation() {
        let header = BlockHeader {
            number: BlockNumber(3),
            extra_data: Bytes::from(<Vec<u8> as Into<Vec<u8>>>::into(hex!("d98301010b846765746888676f312e31382e348664617277696e00004a9b5e4df8aa1fb860adad9d38d885d17320694193adb7c00bbd8106510dbd34e22be7e2734453ecb8bd7eec5c73f277e6c17fab48a67b78680bdc2e731105c0d0e6026233c2456061f1015ebe14b0f1b7f09ecfd7167f860e130d642e16c2d88093331099abbc9c73f84480a040857a8493d09dbbd90ec1652b76d08895b6619cc4bec4f7b271a5711bbe43ce02a04945cfdbb71f49fe7ac9d114b06ff4680182d689a48ab0fbc9ead3308b6f52e8807bc668b22b7e389fa57b5c5e574b023a783ddd8dd1f87ae61e49e1c5b79eedab06896cda389eeb85ddf671d0ab17cbdc025c68d31a453ecefa2206f3473f75b200").into())),
            ..Default::default()
        };
        let chain_spec = mock_chain_sepc();
        let attestation = get_vote_attestation_from_header(&header, &chain_spec, 200)
            .unwrap()
            .unwrap();
        println!("{:?}", attestation);
        let vote_bit_set = BitSet::from_u64(attestation.vote_address_set);
        assert_eq!(5, vote_bit_set.count());
        assert_eq!(true, vote_bit_set.test(0));
        assert_eq!(true, vote_bit_set.test(1));
        assert_eq!(true, vote_bit_set.test(2));
        assert_eq!(true, vote_bit_set.test(3));
        assert_eq!(true, vote_bit_set.test(4));
        assert_eq!(false, vote_bit_set.test(5));
    }

    fn mock_chain_sepc() -> ChainSpec {
        let chain_spec = ChainSpec {
            name: Default::default(),
            consensus: ConsensusParams {
                seal_verification: SealVerificationParams::Parlia {
                    period: 3,
                    epoch: 200,
                },
                eip1559_block: None,
            },
            upgrades: Upgrades {
                boneh: Some(BlockNumber(0)),
                ..Default::default()
            },
            params: Params {
                chain_id: Default::default(),
                network_id: Default::default(),
                additional_forks: Default::default(),
            },
            genesis: Genesis {
                number: Default::default(),
                author: Default::default(),
                gas_limit: 0,
                timestamp: 0,
                seal: Seal::Parlia {
                    vanity: Default::default(),
                    score: BlockScore::NoTurn,
                    signers: vec![],
                    bls_pub_keys: None,
                },
                base_fee_per_gas: None,
            },
            contracts: Default::default(),
            balances: Default::default(),
            p2p: P2PParams {
                bootnodes: vec![],
                dns: None,
            },
        };
        chain_spec
    }
}
