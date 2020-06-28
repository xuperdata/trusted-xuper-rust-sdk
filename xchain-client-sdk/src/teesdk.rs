use std::prelude::v1::*;
use mesatee_sdk::{Mesatee};
use crate::errors::{Error, ErrorKind, Result};

#[derive(Serialize, Deserialize, Debug)]
pub struct EncDecIO {
    pub key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct BinaryOpIn {
    pub l: String,
    pub r: String,
    pub o: String,
    pub commitment: String,
    pub commitment2: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AuthorizeIn {
    pub ciphertext: String,
    pub to: String,
    pub kind: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CommitOut {
    pub commitment: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ShareOut {
    pub cipher: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TFCaller {
    pub method: String,
    pub args: String,
    pub svn: u32,
    pub address: String,
    pub public_key: String,
    pub signature: String,
}

pub fn submit(
    mesatee: &Mesatee,
    worker: &str,
    method: &str,
    args: &str,
    svn: u32,
    addr: &str,
    pubkey: &str,
    sig: &str,
) -> Result<String> {
    let payload = TFCaller {
        method: String::from(method),
        args: String::from(args),
        svn: svn,
        address: String::from(addr),
        public_key: String::from(pubkey),
        signature: String::from(sig),
    };
    let task = mesatee.create_task(worker).unwrap();
    let payload_str = serde_json::to_string(&payload)?;
    let res = task.invoke_with_payload(&payload_str);
    if !res.is_ok() {
        return Err(Error::from(ErrorKind::InvalidArguments));
    }
    Ok(res.unwrap())
}
