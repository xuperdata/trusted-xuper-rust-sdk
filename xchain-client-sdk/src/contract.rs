use super::config;
use crate::errors::{Error, ErrorKind, Result};
use crate::protos;
use crate::{session, wallet};
use std::prelude::v1::*;
extern crate sgx_types;
use crate::protos::xchain;
use sgx_types::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::slice;

/// account在chain上面给to转账amount，小费是fee，留言是des, ocallc
pub fn invoke_contract(
    account: &wallet::Account,
    chain_name: &String,
    method_name: &String,
    args: std::collections::HashMap<String, Vec<u8>>,
) -> Result<String> {
    let mut invoke_req = protos::xchain::InvokeRequest::new();
    invoke_req.set_module_name(String::from("wasm"));
    invoke_req.set_contract_name(account.contract_name.to_owned());
    invoke_req.set_method_name(method_name.to_owned());
    invoke_req.set_args(args);
    invoke_req.set_amount(String::from("0"));

    let invoke_requests = vec![invoke_req; 1];
    let mut auth_requires = vec![];
    if !account.contract_account.is_empty() {
        let mut s = account.contract_account.to_owned();
        s.push_str("/");
        s.push_str(account.address.to_owned().as_str());
        auth_requires.push(s);
    };
    auth_requires.push(
        config::CONFIG
            .read()
            .unwrap()
            .compliance_check
            .compliance_check_endorse_service_addr
            .to_owned(),
    );

    let mut invoke_rpc_request = protos::xchain::InvokeRPCRequest::new();
    invoke_rpc_request.set_bcname(chain_name.to_owned());
    invoke_rpc_request.set_requests(protobuf::RepeatedField::from_vec(invoke_requests));
    invoke_rpc_request.set_initiator(account.address.to_owned());
    invoke_rpc_request.set_auth_require(protobuf::RepeatedField::from_vec(auth_requires.clone()));

    let total_amount = config::CONFIG
        .read()
        .unwrap()
        .compliance_check
        .compliance_check_endorse_service_fee;

    let mut pre_sel_utxo_req = protos::xchain::PreExecWithSelectUTXORequest::new();
    pre_sel_utxo_req.set_bcname(chain_name.to_owned());
    pre_sel_utxo_req.set_address(account.address.to_owned());
    pre_sel_utxo_req.set_totalAmount(total_amount as i64);
    pre_sel_utxo_req.set_request(invoke_rpc_request.clone());

    let msg = session::Message {
        to: Default::default(),
        fee: Default::default(),
        desc: String::from("call from contract"),
        auth_require: auth_requires.clone(),
        amount: Default::default(),
        frozen_height: 0,
        initiator: account.address.to_owned(),
    };

    let sess = session::Session::new(chain_name, account, &msg);
    let mut resp = sess.pre_exec_with_select_utxo(pre_sel_utxo_req)?;

    //TODO 代码优化
    let msg = session::Message {
        to: String::from(""),
        fee: resp.get_response().get_gas_used().to_string(),
        desc: String::from("call from contract"),
        auth_require: auth_requires,
        amount: Default::default(),
        frozen_height: 0,
        initiator: account.address.to_owned(),
    };
    let sess = session::Session::new(chain_name, account, &msg);
    sess.gen_complete_tx_and_post(&mut resp)
}

pub fn query_contract(
    account: &wallet::Account,
    chain_name: &String,
    method_name: &String,
    args: std::collections::HashMap<String, Vec<u8>>,
) -> Result<xchain::InvokeRPCResponse> {
    let mut invoke_req = protos::xchain::InvokeRequest::new();
    invoke_req.set_module_name(String::from("wasm"));
    invoke_req.set_contract_name(account.contract_name.to_owned());
    invoke_req.set_method_name(method_name.to_owned());
    invoke_req.set_args(args);
    let invoke_requests = vec![invoke_req; 1];
    let mut auth_requires = vec![];

    if !account.contract_account.is_empty() {
        let mut s = account.contract_account.to_owned();
        s.push_str("/");
        s.push_str(account.address.to_owned().as_str());
        auth_requires.push(s);
    };

    auth_requires.push(
        config::CONFIG
            .read()
            .unwrap()
            .compliance_check
            .compliance_check_endorse_service_addr
            .to_owned(),
    );

    let mut invoke_rpc_request = protos::xchain::InvokeRPCRequest::new();
    invoke_rpc_request.set_bcname(chain_name.to_owned());
    invoke_rpc_request.set_requests(protobuf::RepeatedField::from_vec(invoke_requests));
    invoke_rpc_request.set_initiator(account.address.to_owned());
    invoke_rpc_request.set_auth_require(protobuf::RepeatedField::from_vec(auth_requires.clone()));

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let req = serde_json::to_string(&invoke_rpc_request)?;

    let mut output = 0 as *mut sgx_libc::c_void;
    let mut out_len: usize = 0;
    let resp = unsafe {
        crate::ocall_xchain_pre_exec(
            &mut rt,
            req.as_ptr() as *const u8,
            req.len(),
            &mut output,
            &mut out_len,
        )
    };

    if resp != sgx_status_t::SGX_SUCCESS || rt != sgx_status_t::SGX_SUCCESS {
        println!(
            "[-] query_contract ocall_xchain_pre_exec failed: {}, {}!",
            resp.as_str(),
            rt.as_str()
        );
        return Err(Error::from(ErrorKind::InvalidArguments));
    }
    unsafe {
        if sgx_types::sgx_is_outside_enclave(output, out_len) == 0 {
            println!("[-] alloc error");
            return Err(Error::from(ErrorKind::InvalidArguments));
        }
    }

    let resp_slice = unsafe { slice::from_raw_parts(output as *mut u8, out_len) };
    let invoke_rpc_resp: xchain::InvokeRPCResponse = serde_json::from_slice(&resp_slice).unwrap();
    unsafe {
        crate::ocall_free(output);
    }
    Ok(invoke_rpc_resp)
}

/*
pub fn test_contract() {
    let bcname = String::from("xuper");
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.push("key/private.key");
    let acc = super::wallet::Account::new(
        d.to_str().unwrap(),
        "counter327861",
        "XC1111111111000000@xuper",
    );

    let mn = String::from("increase");
    let mut args = HashMap::new();
    args.insert(String::from("key"), String::from("counter").into_bytes());

    let txid = invoke_contract(&acc, &bcname, &mn, args);
    println!("contract txid: {:?}", txid);

    assert_eq!(txid.is_ok(), true);
    let txid = txid.unwrap();

    let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
    let mut output = 0 as *mut sgx_libc::c_void;
    let mut out_len: usize = 0;
    let res = unsafe {
        crate::ocall_xchain_query_tx(
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
    let resp_slice = unsafe { slice::from_raw_parts(output as *mut u8, out_len) };
    let result: xchain::TxStatus = serde_json::from_slice(resp_slice).unwrap();
    unsafe {
        crate::ocall_free(output);
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
*/
