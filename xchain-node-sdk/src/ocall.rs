use crate::protos::{xchain, xendorser};
use crate::xchain::XChainClient;
use std::slice;
use std::sync::atomic::{AtomicPtr, Ordering};

#[allow(non_camel_case_types)]
pub enum sgx_status_t {
    SGX_SUCCESS,
    SGX_ERROR_UNEXPECTED,
}

pub static CLI: AtomicPtr<()> = AtomicPtr::new(0 as *mut ());

#[no_mangle]
pub extern "C" fn init(
    bcname: *const u8,
    bcname_size: usize,
    host: *const u8,
    host_size: usize,
    port: u16,
) -> sgx_status_t {
    let bcname = unsafe { slice::from_raw_parts(bcname, bcname_size) };
    let bcname = String::from_utf8(bcname.to_vec());
    let host = unsafe { slice::from_raw_parts(host, host_size) };
    let host = String::from_utf8(host.to_vec());
    if !(bcname.is_ok() && host.is_ok()) {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let bcname = bcname.unwrap();
    let host = host.unwrap();

    let ptr = CLI.load(Ordering::SeqCst);
    if ptr.is_null() {
        let ptr: *mut XChainClient =
            Box::into_raw(Box::new(XChainClient::new(&bcname, &host, port)));
        CLI.store(ptr as *mut (), Ordering::SeqCst);
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn close() {}

#[no_mangle]
pub extern "C" fn ocall_free(p: *mut libc::c_void) {
    unsafe { libc::free(p) }
}

#[no_mangle]
pub extern "C" fn ocall_xchain_endorser_call(
    en_req: *const u8,
    en_req_size: usize,
    output: *mut *mut libc::c_void,
    output_size: *mut usize,
) -> sgx_status_t {
    let en_req_slice = unsafe { slice::from_raw_parts(en_req, en_req_size) };
    let en_req: xendorser::EndorserRequest = serde_json::from_slice(&en_req_slice).unwrap();

    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { &(*ptr) };
    let res = cli.call(en_req);
    if !res.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let res = res.unwrap();

    let s = serde_json::to_string(&res);
    if !s.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let s = s.unwrap();

    unsafe {
        *output = libc::malloc(s.len());
        if output.is_null() {
            return sgx_status_t::SGX_ERROR_UNEXPECTED
        }
        std::ptr::copy_nonoverlapping(s.as_ptr(), *(output as *mut *mut u8), s.len());
        *output_size = s.len();
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_xchain_post_tx(req: *const u8, req_size: usize) -> sgx_status_t {
    let req_slice = unsafe { slice::from_raw_parts(req, req_size) };
    let req: xchain::Transaction = serde_json::from_slice(&req_slice).unwrap();

    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { &(*ptr) };

    match cli.post_tx(&req) {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(_) => sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}

#[no_mangle]
pub extern "C" fn ocall_xchain_query_tx(
    txid: *const u8,
    txid_size: usize,
    output: *mut *mut libc::c_void,
    output_size: *mut usize,
) -> sgx_status_t {
    let req_slice = unsafe { slice::from_raw_parts(txid, txid_size) };
    let txid = String::from_utf8(req_slice.to_vec());
    if !txid.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let txid = txid.unwrap();

    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { &(*ptr) };
    let res = cli.query_tx(&txid);
    if !res.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let res = res.unwrap();

    let s = serde_json::to_string(&res);
    if !s.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let s = s.unwrap();
    unsafe {
        *output = libc::malloc(s.len());
        if output.is_null() {
            return sgx_status_t::SGX_ERROR_UNEXPECTED
        }
        std::ptr::copy_nonoverlapping(s.as_ptr(), *(output as *mut *mut u8), s.len());
        *output_size = s.len();
    }
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn ocall_xchain_pre_exec(
    req: *const u8,
    req_size: usize,
    output: *mut *mut libc::c_void,
    output_size: *mut usize,
) -> sgx_status_t {
    let req_slice = unsafe { slice::from_raw_parts(req, req_size) };
    let req: xchain::InvokeRPCRequest = serde_json::from_slice(&req_slice).unwrap();

    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { &(*ptr) };
    let res = cli.pre_exec(req);
    if !res.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let res = res.unwrap();

    let s = serde_json::to_string(&res);
    if !s.is_ok() {
        return sgx_status_t::SGX_ERROR_UNEXPECTED
    }
    let s = s.unwrap();

    unsafe {
        *output = libc::malloc(s.len());
        if output.is_null() {
            return sgx_status_t::SGX_ERROR_UNEXPECTED
        }
        std::ptr::copy_nonoverlapping(s.as_ptr(), *(output as *mut *mut u8), s.len());
        *output_size = s.len();
    }
    sgx_status_t::SGX_SUCCESS
}
