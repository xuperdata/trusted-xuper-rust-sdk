use rand::rngs::StdRng;
use rand_core::{RngCore, SeedableRng};
use xchain_crypto::sign::ecdsa::KeyPair;

/// 保管私钥，提供签名和验签
/// 要在TEE里面运行
/// 唯一可以调用xchain_crypto的地方
use xchain_node_sdk::errors::*;

/// 加载钱包地址或者加载enclave
#[derive(Default, Debug)]
pub struct Account {
    pub contract_name: String,
    pub contract_account: String,
    pub address: String,
    pub path: String,
}

impl Account {
    pub fn new(path: &str, contract_name: &str, contract_account: &str) -> Self {
        //加载私钥: features: normal | sgx | trustzone
        let p = xchain_crypto::account::get_ecdsa_private_key_from_file(path).expect("load key");
        let alg = &xchain_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let pk = xchain_crypto::account::PublicKey::new(alg, p.public_key());
        let address =
            xchain_crypto::account::address::get_address_from_public_key(&pk).expect("load key");
        Account {
            address: address,
            path: path.to_string(),
            contract_account: contract_account.to_string(),
            contract_name: contract_name.to_string(),
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let p = xchain_crypto::account::get_ecdsa_private_key_from_file(&self.path)?;
        Ok(p.sign(msg)?.as_ref().to_vec())
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        let p = xchain_crypto::account::get_ecdsa_private_key_from_file(&self.path)?;
        let alg = &xchain_crypto::sign::ecdsa::ECDSA_P256_SHA256_ASN1;
        let pk = xchain_crypto::account::PublicKey::new(alg, p.public_key());
        pk.verify(msg, sig)?;
        Ok(())
    }

    pub fn public_key(&self) -> Result<String> {
        let p = xchain_crypto::account::get_ecdsa_private_key_from_file(&self.path)?;
        let res = xchain_crypto::account::json_key::get_ecdsa_public_key_json_format_in_go(&p)?;
        Ok(res)
    }

    // TODO  把其他所有crypto相关的操作移动到这里
}

pub fn get_nonce() -> Result<String> {
    let t = super::consts::now_as_secs();
    let m: u32 = 100000000;

    let seed = xchain_crypto::hdwallet::rand::generate_seed_with_strength_and_keylen(
        xchain_crypto::hdwallet::rand::KeyStrength::HARD,
        64,
    )?;
    let mut same_seed = [0u8; 32];
    same_seed.copy_from_slice(&seed[..32]);
    let mut rng = StdRng::from_seed(same_seed);
    let r = rng.next_u32() % m;

    Ok(format!("{}{:08}", t, r))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_load_account() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("key/private.key");
        let acc = Account::new(d.to_str().unwrap(), "counter", "XC1111111111000000@xuper");
        println!("{:?}", acc);
        let address = include_str!("../key/address");
        assert_eq!(acc.address, address);
    }
}
