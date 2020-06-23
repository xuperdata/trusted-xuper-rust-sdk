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
    let mut args = HashMap::new();
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
    let acc = super::wallet::Account::new(
        d.to_str().unwrap(),
        "counter327861",
        "XC1111111111000000@xuper",
    );
    let mn = String::from("get");
    let mut args = HashMap::new();
    args.insert(String::from("key"), String::from("counter").into_bytes());

    let resp = query_contract(&acc, &bcname, &mn, args);
    assert_eq!(resp.is_ok(), true);
    println!("contract query response: {:?}", resp);
    println!("contract query test passed");
}

