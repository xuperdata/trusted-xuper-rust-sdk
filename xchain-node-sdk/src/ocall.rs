use crate::errors::Result;
use crate::protos::{xchain, xendorser};
use crate::xchain::XChainClient;

#[no_mangle]
pub extern "C" fn ocall_xchain_endorser_call(
    bcname: &String,
    host: &String,
    port: u16,
    en_req: xendorser::EndorserRequest,
) -> Result<xendorser::EndorserResponse> {
    let cli = XChainClient::new(&bcname, host, port);
    cli.call(en_req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_post_tx(
    bcname: &String,
    host: &String,
    port: u16,

    req: &xchain::Transaction,
) -> Result<()> {
    let cli = XChainClient::new(&bcname, host, port);
    cli.post_tx(req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_query_tx(
    bcname: &String,
    host: &String,
    port: u16,
    txid: &String,
) -> Result<xchain::TxStatus> {
    let cli = XChainClient::new(&bcname, host, port);
    cli.query_tx(&txid)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_pre_exec(
    bcname: &String,
    host: &String,
    port: u16,
    req: xchain::InvokeRPCRequest,
) -> Result<xchain::InvokeRPCResponse> {
    let cli = XChainClient::new(&bcname, host, port);
    cli.pre_exec(req)
}
