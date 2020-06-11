use futures::executor;
use grpc::ClientStubExt;

use crate::errors::{Error, ErrorKind, Result};
use crate::protos::xendorser_grpc;
use crate::protos::{xchain, xchain_grpc, xendorser};

pub struct XChainClient {
    pub chain_name: String,

    pub endorser: xendorser_grpc::xendorserClient,

    pub xchain: xchain_grpc::XchainClient,
}

#[allow(dead_code)]
impl XChainClient {
    pub fn new(bcname: &String, host: &String, port: u16) -> Self {
        //TODO: 设置超时，以及body大小
        let client_conf = Default::default();
        let client_endorser = xendorser_grpc::xendorserClient::new_plain(host, port, client_conf)
            .expect("new connection");

        let client_conf = Default::default();
        let client_xchain =
            xchain_grpc::XchainClient::new_plain(host, port, client_conf).expect("new connection");

        XChainClient {
            chain_name: bcname.to_owned(),
            endorser: client_endorser,
            xchain: client_xchain,
        }
    }

    pub fn call(&self, r: xendorser::EndorserRequest) -> Result<xendorser::EndorserResponse> {
        let resp = self
            .endorser
            .endorser_call(grpc::RequestOptions::new(), r)
            .drop_metadata();
        Ok(executor::block_on(resp)?)
    }

    pub fn check_resp_code(&self, resp: &[xchain::ContractResponse]) -> Result<()> {
        for i in resp.iter() {
            if i.status > 400 {
                return Err(Error::from(ErrorKind::ContractCodeGT400));
            }
        }
        Ok(())
    }

    pub fn post_tx(&self, tx: &xchain::Transaction) -> Result<()> {
        let mut tx_status = xchain::TxStatus::new();
        tx_status.set_bcname(self.chain_name.to_owned());
        tx_status.set_status(xchain::TransactionStatus::UNCONFIRM);
        tx_status.set_tx(tx.clone());
        tx_status.set_txid(tx.txid.clone());
        let resp = self
            .xchain
            .post_tx(grpc::RequestOptions::new(), tx_status)
            .drop_metadata();
        let resp = executor::block_on(resp).unwrap();
        if resp.get_header().error != xchain::XChainErrorEnum::SUCCESS {
            println!("post tx failed, {:?}", resp);
            return Err(Error::from(ErrorKind::ParseError));
        }
        Ok(())
    }

    pub fn query_tx(&self, txid: &String) -> Result<xchain::TxStatus> {
        let mut tx_status = xchain::TxStatus::new();
        tx_status.set_bcname(self.chain_name.to_owned());
        tx_status.set_txid(hex::decode(txid)?);
        let resp = self
            .xchain
            .query_tx(grpc::RequestOptions::new(), tx_status)
            .drop_metadata();
        let resp = executor::block_on(resp).unwrap();

        if resp.get_header().error != xchain::XChainErrorEnum::SUCCESS {
            return Err(Error::from(ErrorKind::ChainRPCError));
        }
        // TODO check txid if null
        Ok(resp)
    }

    pub fn pre_exec(
        &self,
        invoke_rpc_req: xchain::InvokeRPCRequest,
    ) -> Result<xchain::InvokeRPCResponse> {
        let resp = self
            .xchain
            .pre_exec(grpc::RequestOptions::new(), invoke_rpc_req)
            .drop_metadata();
        let resp = executor::block_on(resp).unwrap();
        self.check_resp_code(resp.get_response().get_responses())?;
        Ok(resp)
    }
}
