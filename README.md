## xuper-rust-sdk

A Xuperchain SDK by rust, especially for TEE(Intel SGX/ARM TZ) application.

## Requirements

XuperChain 3.7

## Function

- [x] load account
- [x] Transfer
- [x] Contract Invoke/Query
- [ ] balance

## Notices when serializing

In protos/xchain.rs and protos/xendorser.rs:
* Serialize enum as number: https://serde.rs/enum-number.html
* #[serde(default)]
* crate::wallet::*


## Test

1、Install SGX 2.9.1: [Here](https://github.com/xuperdata/mesatee-core-standalone/blob/master/docs/SGX2.9.1%E5%8D%87%E7%BA%A7%E6%8C%87%E5%8D%97.md)

2、sdk-sgx-test/enclave/src/lib.rs测试文件中的全局变量PUBKEY_PATH、SIG_PATH、ENCLAVE_PATH按照具体情况填写。

3、make and run tests
```
cd sdk-sgx-test
make
cd bin
export IAS_SPID=xxxx
export IAS_KEY=xxx
./run-tests
```

## Call KMS in TEE

Import [trusted-mesatee-sdk](./trusted-mesatee-sdk/mesatee_sdk) in your project. 

