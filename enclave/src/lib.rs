#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

use std::prelude::v1::*;
extern crate serde_yaml;

#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate serde_json;

extern crate sgx_types;
use sgx_types::*;

#[macro_use]
extern crate serde_derive;

pub mod consts;
pub mod contract;

pub mod config;
pub mod session;
pub mod transfer;
pub mod wallet;
pub mod encoder;
pub mod errors;

pub mod protos;

extern "C" {
    pub fn init ( ret_val : *mut sgx_status_t,
        bcname: *const u8,
        bcname_size: usize,
        host: *const u8,
        host_size: usize,
        port: u16,
    ) -> sgx_status_t;

    pub fn close();

    pub fn ocall_free(p: *mut sgx_libc::c_void);

    pub fn ocall_xchain_endorser_call ( ret_val : *mut sgx_status_t,
        en_req: *const u8,
        en_req_size: usize,
        output: *mut *mut sgx_libc::c_void,
        output_size: *mut usize,
    ) -> sgx_status_t;

    pub fn ocall_xchain_post_tx ( ret_val : *mut sgx_status_t,
        req: *const u8,
        req_size: usize,
    ) -> sgx_status_t;

    pub fn ocall_xchain_query_tx( ret_val : *mut sgx_status_t,
                                  txid: *const u8,
                                  txid_size: usize,
                                  output: *mut *mut sgx_libc::c_void,
                                  output_size: *mut usize,
    ) -> sgx_status_t;

    pub fn ocall_xchain_pre_exec( ret_val : *mut sgx_status_t,
        req: *const u8,
        req_size: usize,
        output: *mut *mut sgx_libc::c_void,
        output_size: *mut usize,
    ) -> sgx_status_t;
}

#[no_mangle]
pub extern "C" fn ecall_run_tests() -> sgx_status_t {
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let bcname = String::from("xuper");
    let host = config::CONFIG.read().unwrap().node.clone();
    let port = config::CONFIG.read().unwrap().endorse_port;

    let res = unsafe {
        init(&mut rt as *mut sgx_status_t,
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

    wallet::test_load_account();
    transfer::test_transfer();
    contract::test_contract();
    contract::test_query();

    unsafe {
        close();
    }

    println!("passed all tests");
    sgx_status_t::SGX_SUCCESS
}
