## trusted-xuper-rust-sdk

A Xuperchain SDK by rust, especially for TEE(Intel SGX/ARM TZ) application.

## Requirements

1. Xuperchain 3.7

    Clone xuperchain [source code](https://github.com/xuperchain/xuperchain/tree/v3.7) and follow the [instruction](https://github.com/xuperchain/xuperchain/wiki/3.-Getting-Started) to build a single-node or multi-node network.

    If you would like to enable mesatee functionality, continue with step 2 and step 3.

2.  SGX 2.9.1
    Follow the [instruction](https://github.com/xuperdata/mesatee-core-standalone/blob/master/docs/SGX2.9.1%E5%8D%87%E7%BA%A7%E6%8C%87%E5%8D%97.md) to set up a sgx2.9.1 development environment.

3. Mesatee-core-standalone

   Follow the [instruction](https://github.com/xuperdata/mesatee-core-standalone) to set up mesatee service.

## Function

- [x] load account
- [x] Transfer
- [x] Contract Invoke/Query
- [ ] balance
- [x] mesatee trust functions

## Notices when serializing

In protos/xchain.rs and protos/xendorser.rs:
* Serialize enum as number: https://serde.rs/enum-number.html
* \#[serde(default)]
* crate::wallet::*

## Test

1. Xuperchain configuraton

    You may need to modify the xuperchain configuration in file "xchain-client-sdk/conf/sdk.yaml" according to your xuperchain network.

2. Mesatee configuraton

    You can choose to test mesatee trust functions by adding "mesatee-sdk" to the default feature in "sdk-sgx-test/enclave/Cargo.toml". Remove it if you choose not to enable mesatee functionality.

    You may need to modify the value of global parameters at the beginning of test file "sdk-sgx-test/enclave/src/lib.rs". "PUBKEY_PATH", "SIG_PATH" and "ENCLAVE_PATH" refer to mesacore-core-standalone/release/services directory.

    You may need to modify the value of [n_worker](https://github.com/xuperdata/mesatee-core-standalone/blob/master/mesatee_services/fns/sgx_app/src/main.rs) and [TCSnum](https://github.com/xuperdata/mesatee-core-standalone/blob/master/mesatee_services/fns/sgx_trusted_lib/Enclave.config.xml) to achieve higher concurrency.

3. make and run tests
```
cd sdk-sgx-test
make
cd bin
export IAS_SPID=xxxx (only when "mesatee-sdk" is enabled)
export IAS_KEY=xxx (only when "mesatee-sdk" is enabled)
./run-tests
```

## Call KMS in TEE

Import [trusted-mesatee-sdk](./trusted-mesatee-sdk/mesatee_sdk) in your project. 

