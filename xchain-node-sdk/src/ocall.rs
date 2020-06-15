use crate::errors::Result;
use crate::protos::{xchain, xendorser};
use crate::xchain::XChainClient;
use std::sync::atomic::{AtomicPtr, Ordering};

pub static CLI: AtomicPtr<()> = AtomicPtr::new(0 as *mut ());

#[no_mangle]
pub extern "C" fn init(
    bcname: &String,
    host: &String,
    port: u16,
) -> Result<()> {
    let ptr = CLI.load(Ordering::SeqCst);
    if ptr.is_null() {
        let ptr: *mut XChainClient = Box::into_raw(Box::new(XChainClient::new(&bcname, host, port)));
        CLI.store(ptr as *mut (), Ordering::SeqCst);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn close(){}

#[no_mangle]
pub extern "C" fn ocall_xchain_endorser_call(
    en_req: xendorser::EndorserRequest,
) -> Result<xendorser::EndorserResponse> {
    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { & (*ptr) };
    cli.call(en_req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_post_tx(
    req: &xchain::Transaction,
) -> Result<()> {
    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { & (*ptr) };
    cli.post_tx(req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_query_tx(
    txid: &String,
) -> Result<xchain::TxStatus> {
    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { & (*ptr) };
    cli.query_tx(&txid)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_pre_exec(
    req: xchain::InvokeRPCRequest,
) -> Result<xchain::InvokeRPCResponse> {
    let ptr: *mut XChainClient = CLI.load(Ordering::SeqCst) as *mut XChainClient;
    let cli = unsafe { & (*ptr) };
    cli.pre_exec(req)
}
