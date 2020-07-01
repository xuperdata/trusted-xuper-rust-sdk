#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

use std::prelude::v1::*;

extern crate sgx_types;
use sgx_types::*;

use std::path::PathBuf;

#[macro_use]
extern crate lazy_static;

use hex;
#[cfg(feature = "mesatee-sdk")]
use mesatee_sdk::{Mesatee, MesateeEnclaveInfo};
use std::net::SocketAddr;
use xchain_client_sdk::teesdk;

lazy_static! {
    static ref OWNER: String = String::from("dy9UjyBbELfdWHZFUNXkdaaCmTWLkUeyy");
    static ref USER: String = String::from("ZsPy7eELS55MXALUhAynUtjsxjeKFbwqy");
    static ref USER_ID: String = String::from("user1");
    static ref USER_TOKEN: String = String::from("token1");
    static ref FNS_ADDR: SocketAddr = "127.0.0.1:8082".parse().unwrap();
    static ref PUBKEY_PATH: String = String::from("auditors/godzilla/godzilla.public.der");
    static ref SIG_PATH: String = String::from("auditors/godzilla/godzilla.sign.sha256");
    static ref ENCLAVE_PATH: String = String::from("enclave_info.toml");
    static ref PLAIN1: String = String::from("25");
    static ref PLAIN2: String = String::from("12");
    static ref ADDITION: String = String::from("37");
}

#[no_mangle]
pub extern "C" fn ecall_run_tests() -> sgx_status_t {
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let bcname = String::from("xuper");
    let host = xchain_client_sdk::config::CONFIG.read().unwrap().node.clone();
    let port = xchain_client_sdk::config::CONFIG.read().unwrap().endorse_port;

    let res = unsafe {
        xchain_client_sdk::init(&mut rt as *mut sgx_status_t,
             bcname.as_ptr() as * const u8,
             bcname.len(),
             host.as_ptr() as * const u8,
             host.len(),
             port)
    };

    if res != sgx_status_t::SGX_SUCCESS || rt != sgx_status_t::SGX_SUCCESS {
        println!("init xchainClient failed: {}, {}", res.as_str(), rt.as_str());
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    println!("init xchainClient success");

    test_load_account();
    test_transfer();
    test_contract();
    test_query();

    #[cfg(feature = "mesatee-sdk")]
    test_trust_function();

    unsafe {
        xchain_client_sdk::close();
    }

    println!("passed all tests");
    sgx_status_t::SGX_SUCCESS
}

fn test_load_account() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    println!("tets_load_account: {:?}", d);
    d.push("key/private.key");
    
    let acc = xchain_client_sdk::wallet::Account::new(d.to_str().unwrap(), "counter", "XC1111111111000000@xuper");
    println!("{:?}", acc);
    let address = include_str!("../key/address");
    assert_eq!(acc.address, address);
    println!("load account test passed");
}

pub fn test_transfer() {
    let bcname = String::from("xuper");
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("key/private.key");
    let acc = xchain_client_sdk::wallet::Account::new(
        d.to_str().unwrap(),
        Default::default(),
        "XC1111111111000000@xuper",
    );
    let to = "dpzuVdosQrF2kmzumhVeFQZa1aYcdgFpN".to_string();
    let amount = "1401".to_string();
    let fee = "0".to_string();
    let desc = "test duanbing".to_string();

    let res = xchain_client_sdk::transfer::transfer(&acc, &bcname, &to, &amount, &fee, &desc);
    println!("transfer res: {:?}", res);
    assert_eq!(res.is_ok(), true);
    let txid = res.unwrap();
    println!("txid: {:?}", txid);

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut output = 0 as *mut sgx_libc::c_void;
    let mut out_len: usize = 0;
    let res = unsafe {
        xchain_client_sdk::ocall_xchain_query_tx(
            &mut rt,
            txid.as_ptr() as *const u8,
            txid.len(),
            &mut output,
            &mut out_len,
        )
    };
    assert_eq!(res, sgx_status_t::SGX_SUCCESS);
    assert_eq!(rt, sgx_status_t::SGX_SUCCESS);
    unsafe {
        assert_ne!(sgx_types::sgx_is_outside_enclave(output, out_len), 0);
    }
    let resp_slice = unsafe { std::slice::from_raw_parts(output as *mut u8, out_len) };
    let result: xchain_client_sdk::protos::xchain::TxStatus = serde_json::from_slice(resp_slice).unwrap();
    unsafe {
        xchain_client_sdk::ocall_free(output);
    }
    println!("{:?}", result);
    println!("transfer test passed");
}

pub fn test_contract() {
    let bcname = String::from("xuper");
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("key/private.key");
    let acc = xchain_client_sdk::wallet::Account::new(
        d.to_str().unwrap(),
        "counter327861",
        "XC1111111111000000@xuper",
    );

    let mn = String::from("increase");
    let mut args = std::collections::HashMap::new();
    args.insert(String::from("key"), String::from("counter").into_bytes());

    let txid = xchain_client_sdk::contract::invoke_contract(&acc, &bcname, &mn, args);
    println!("contract txid: {:?}", txid);

    assert_eq!(txid.is_ok(), true);
    let txid = txid.unwrap();

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut output = 0 as *mut sgx_libc::c_void;
    let mut out_len: usize = 0;
    let res = unsafe {
        xchain_client_sdk::ocall_xchain_query_tx(
            &mut rt,
            txid.as_ptr() as *const u8,
            txid.len(),
            &mut output,
            &mut out_len,
        )
    };
    assert_eq!(res, sgx_status_t::SGX_SUCCESS);
    assert_eq!(rt, sgx_status_t::SGX_SUCCESS);
    unsafe {
        assert_ne!(sgx_types::sgx_is_outside_enclave(output, out_len), 0);
    }
    let resp_slice = unsafe { std::slice::from_raw_parts(output as *mut u8, out_len) };
    let result: xchain_client_sdk::protos::xchain::TxStatus = serde_json::from_slice(resp_slice).unwrap();
    unsafe {
        xchain_client_sdk::ocall_free(output);
    }
    println!("{:?}", result);
    println!("invoke contract test passed");
}

pub fn test_query() {
    let bcname = String::from("xuper");
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("key/private.key");
    let acc = xchain_client_sdk::wallet::Account::new(
        d.to_str().unwrap(),
        "counter327861",
        "XC1111111111000000@xuper",
    );
    let mn = String::from("get");
    let mut args = std::collections::HashMap::new();
    args.insert(String::from("key"), String::from("counter").into_bytes());

    let resp = xchain_client_sdk::contract::query_contract(&acc, &bcname, &mn, args);
    assert_eq!(resp.is_ok(), true);
    println!("contract query response: {:?}", resp);
    println!("contract query test passed");
}

#[cfg(feature = "mesatee-sdk")]
fn test_trust_function() {
    // initialize parameters
    println!("***init parameters***");
    let mut auditors: Vec<(&str, &str)> = Vec::new();
    auditors.push((&PUBKEY_PATH, &SIG_PATH));
    let enclave_info: MesateeEnclaveInfo =
        MesateeEnclaveInfo::load(auditors, &ENCLAVE_PATH).unwrap();
    let mesatee: Mesatee = Mesatee::new(&enclave_info, &USER_ID, &USER_TOKEN, *FNS_ADDR).unwrap();

    // load account
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("key/private.key");
    let acc = xchain_client_sdk::wallet::Account::new(d.to_str().unwrap(), "counter", "XC1111111111000000@xuper");
    println!("{:?}", acc);
    let address = include_str!("../key/address");
    assert_eq!(acc.address, address);
    println!("load account test passed");

    // test encryption
    println!("***test encryption***");
    let args = teesdk::EncDecIO {
        key: PLAIN1.to_string(),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("encrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let pubkey_hex = "04a24cf1352cd8d21be0567ce730cc9a78f5269d2eeabc44e5cb7aa01cd76ac50c0157f847b864048021d9116dc799b1c4659aeffb5606c4b28801b287eb709de8";
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "encrypt",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    println!("{:?}", result);
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let cipher1 = &res.key;
    println!("cipher1: {:?}", cipher1);

    // encrypt plain2 by owner
    let args = teesdk::EncDecIO {
        key: PLAIN2.to_string(),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("encrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "encrypt",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.ok().unwrap()).unwrap();
    let cipher2 = &res.key;
    println!("cipher2: {:?}", cipher2);

    // test decryption
    println!("***test decryption***");
    let args = teesdk::EncDecIO {
        key: String::from(cipher1),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("decrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "decrypt",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let plain1_decrypted = &res.key;
    let plain1_decrypted = base64::decode(plain1_decrypted).unwrap();
    let plain1_decrypted = String::from_utf8(plain1_decrypted).unwrap();
    println!("decrypted plain1: {:?}", &plain1_decrypted);
    assert_eq!(&plain1_decrypted, &PLAIN1.to_string());

    // decrypt cipher2 by owner
    let args = teesdk::EncDecIO {
        key: String::from(cipher2),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("decrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "decrypt",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let plain2_decrypted = &res.key;
    let plain2_decrypted = base64::decode(plain2_decrypted).unwrap();
    let plain2_decrypted = String::from_utf8(plain2_decrypted).unwrap();
    println!("decrypted plain2: {:?}", &plain2_decrypted);
    assert_eq!(&plain2_decrypted, &PLAIN2.to_string());

    // test authorization
    println!("***test authorization***");
    let args = teesdk::AuthorizeIn {
        ciphertext: String::from(cipher1),
        to: USER.to_string(),
        kind: String::from("commitment"),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("authorize");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "authorize",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::CommitOut = serde_json::from_str(&result.unwrap()).unwrap();
    let commitment1 = &res.commitment;
    println!("commitment1: {:?}", &commitment1);

    // get commitment2
    let args = teesdk::AuthorizeIn {
        ciphertext: String::from(cipher2),
        to: USER.to_string(),
        kind: String::from("commitment"),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("authorize");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "authorize",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::CommitOut = serde_json::from_str(&result.unwrap()).unwrap();
    let commitment2 = &res.commitment;
    println!("commitment2: {:?}", commitment2);

    // test addition by user
    println!("***test addition by user***");
    let args = teesdk::BinaryOpIn {
        l: String::from(cipher1),
        r: String::from(cipher2),
        o: String::from("key"),
        commitment: String::from(commitment1),
        commitment2: String::from(commitment2),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "add",
        &args_str,
        0,
        &USER,
        "",
        "",
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let cipher_add = &res.key;
    println!("cipher_add: {:?}", &cipher_add);

    // decrypt addition by user
    let args = teesdk::EncDecIO {
        key: String::from(cipher_add),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("decrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "decrypt",
        &args_str,
        0,
        &USER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let plain_add = &res.key;
    let plain_add = base64::decode(plain_add).unwrap();
    let plain_add = String::from_utf8(plain_add).unwrap();
    println!("plain_add: {:?}", &plain_add);
    assert_eq!(&plain_add, &ADDITION.to_string());

    // test share
    println!("***test share***");
    let args = teesdk::AuthorizeIn {
        ciphertext: String::from(cipher1),
        to: USER.to_string(),
        kind: String::from("ownership"),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("authorize");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "authorize",
        &args_str,
        0,
        &OWNER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::ShareOut = serde_json::from_str(&result.unwrap()).unwrap();
    let cipher_share = &res.cipher;
    println!("cipher share to user: {:?}", &cipher_share);

    // decrypt cipher1 by user
    let args = teesdk::EncDecIO {
        key: String::from(cipher_share),
    };
    let args_str = serde_json::to_string(&args).unwrap();
    let mut args = String::from("decrypt");
    args.push_str(&args_str);
    let sig = acc.sign(args.as_bytes()).unwrap();
    let sig_hex = hex::encode(sig);
    let result = teesdk::submit(
        &mesatee,
        "xchaintf",
        "decrypt",
        &args_str,
        0,
        &USER,
        &pubkey_hex,
        &sig_hex,
    );
    assert_eq!(result.is_ok(), true);
    let res: teesdk::EncDecIO = serde_json::from_str(&result.unwrap()).unwrap();
    let plain_share = &res.key;
    let plain_share = base64::decode(plain_share).unwrap();
    let plain_share = String::from_utf8(plain_share).unwrap();
    println!("plain share to user: {:?}", &plain_share);
    assert_eq!(&plain_share, &PLAIN1.to_string());
}
