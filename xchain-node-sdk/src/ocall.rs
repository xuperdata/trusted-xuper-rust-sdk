use crate::errors::Result;
use crate::protos::{xchain, xendorser};
use crate::xchain::XChainClient;

#[no_mangle]
pub extern "C" fn ocall_xchain_endorser_call(
    bcname: &String,
    en_req: xendorser::EndorserRequest,
) -> Result<xendorser::EndorserResponse> {
    let cli = XChainClient::new(&bcname);
    cli.call(en_req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_post_tx(bcname: &String, req: &xchain::Transaction) -> Result<()> {
    let cli = XChainClient::new(&bcname);
    cli.post_tx(req)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_query_tx(
    bcname: &String,
    txid: &String,
) -> Result<xchain::TxStatus> {
    let cli = XChainClient::new(&bcname);
    cli.query_tx(&txid)
}

#[no_mangle]
pub extern "C" fn ocall_xchain_pre_exec(
    bcname: &String,
    req: xchain::InvokeRPCRequest,
) -> Result<xchain::InvokeRPCResponse> {
    let cli = XChainClient::new(&bcname);
    cli.pre_exec(req)
}
