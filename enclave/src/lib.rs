#![cfg_attr(all(feature = "mesalock_sgx",
                not(target_env = "sgx")), no_std)]
#![cfg_attr(all(target_env = "sgx", target_vendor = "mesalock"), feature(rustc_private))]

#[cfg(all(feature = "mesalock_sgx", not(target_env = "sgx")))]
#[macro_use]
extern crate sgx_tstd as std;

/* #![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#[cfg(not(target_env = "sgx"))] */

use std::prelude::v1::*;

extern crate serde_yaml;
//extern crate xchain_node_sdk;

#[macro_use]
extern crate lazy_static;
extern crate rand;
extern crate serde_json;

extern crate sgx_types;
use std::time::*;
use sgx_types::*;
use std::ptr;

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
}

#[no_mangle]
pub extern "C" fn ecall_run_tests() {
    //wheel::tests::run_tests();
    let mut rt : sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

    let res = unsafe {
        init(&mut rt as *mut sgx_status_t, ptr::null(), 0, ptr::null(), 0, 1)
    };

    //close();
    println!("abc {}", res);
}
