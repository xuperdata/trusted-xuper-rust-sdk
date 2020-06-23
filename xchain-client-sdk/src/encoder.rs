/// 本文件主要是为了兼容golang的json序列化格式，主要注意事项如下:
/// 1. 序列顺序
/// 2. 枚举是以数字存储，枚举值是0的不会被序列化
/// 3. 默认值初始化的字段不会被序列化，例如0，空字符串，但是空数组是null
/// 4. map按照字典序排列之后再序列化
/// 5. bytes需要base64
/// 6. https://github.com/golang/go/issues/28154   bigint 在golang序列化成json之后还是整数，但是float是字符串
use std::prelude::v1::*;
use crate::errors::Result;
use crate::protos::xchain;
use serde::de::{MapAccess, Visitor};
use std::marker::PhantomData;

use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

fn encode_bytes(v: &Vec<u8>, buf: &mut String) -> Result<()> {
    if v.len() == 0 {
        return Ok(());
    }
    let b64 = base64::encode(v);
    let ti = serde_json::to_string(&b64)?;
    buf.push_str(&ti);
    buf.push('\n');
    Ok(())
}

pub fn serialize_bytes<S>(v: &Vec<u8>, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    if v.len() == 0 {
        return serializer.serialize_none();
    }
    let b64 = base64::encode(v);
    serializer.serialize_str(&b64)
}

pub fn deserialize_bytes<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s = String::deserialize(deserializer)?;
    let b64 = base64::decode(&s).map_err(Error::custom)?;
    Ok(b64)
}

pub fn serialize_bytes_arr<S>(
    v: &protobuf::RepeatedField<Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    let mut seq = serializer.serialize_seq(Some(v.len()))?;
    for e in v.iter() {
        let b64 = base64::encode(e);
        seq.serialize_element(&b64)?;
    }
    seq.end()
}

pub fn deserialize_bytes_arr<'de, D>(
    deserializer: D,
) -> std::result::Result<protobuf::RepeatedField<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let mut vec = Vec::new();
    let res = Vec::<u8>::deserialize(deserializer);
    for elem in res.iter() {
        let b64 = base64::decode(&elem).map_err(Error::custom)?;
        vec.push(b64);
    }
    Ok(protobuf::RepeatedField::from_vec(vec))
}

fn encode_array<T>(arr: &Vec<T>, buf: &mut String) -> Result<()>
where
    T: serde::ser::Serialize,
{
    if arr.len() > 0 {
        let s = serde_json::to_string(arr)?;
        buf.push_str(&s);
        buf.push('\n');
        return Ok(());
    }
    // push null
    buf.push('n');
    buf.push('u');
    buf.push('l');
    buf.push('l');
    buf.push('\n');
    Ok(())
}

pub fn is_zero(t: &i64) -> bool {
    t == &0
}

#[allow(non_snake_case)]
pub fn is_CPU(t: &crate::protos::xchain::ResourceType) -> bool {
    match t {
        crate::protos::xchain::ResourceType::CPU => true,
        _ => false,
    }
}

pub fn is_empty<T>(t: &protobuf::RepeatedField<T>) -> bool {
    t.is_empty()
}

pub fn serialize_ordered_map<S>(
    value: &HashMap<String, Vec<u8>>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let ordered: BTreeMap<_, _> = value.iter().collect();
    let mut res = BTreeMap::new();
    for (k, v) in ordered.iter() {
        res.insert(k, base64::encode(v));
    }
    res.serialize(serializer)
}

#[derive(Debug)]
struct MyMapVisitor<K, V> {
    marker: PhantomData<fn() -> HashMap<K, V>>,
}

impl<K, V> MyMapVisitor<K, V> {
    fn new() -> Self {
        MyMapVisitor {
            marker: PhantomData,
        }
    }
}

impl<'de, K, V> Visitor<'de> for MyMapVisitor<K, V>
where
    K: Deserialize<'de> + std::hash::Hash + std::cmp::Eq + std::fmt::Debug,
    V: Deserialize<'de> + std::fmt::Debug + AsRef<[u8]>,
{
    // The type that our Visitor is going to produce.
    type Value = HashMap<K, V>;

    // Format a message stating what data this Visitor expects to receive.
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a very special map")
    }

    // Deserialize MyMap from an abstract "map" provided by the
    // Deserializer. The MapAccess input is a callback provided by
    // the Deserializer to let us see each entry in the map.
    fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut map = HashMap::with_capacity(access.size_hint().unwrap_or(0));
        // While there are entries remaining in the input, add them
        // into our map.
        while let Some((key, value)) = access.next_entry()? {
            map.insert(key, value);
        }
        Ok(map)
    }
}

pub fn deserialize_ordered_map<'de, D>(
    deserializer: D,
) -> std::result::Result<HashMap<String, Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let res = deserializer.deserialize_map(MyMapVisitor::<String, String>::new())?;
    let mut ret = HashMap::new();
    for (k, v) in res.iter() {
        let b64 = base64::decode(&v).map_err(Error::custom)?;
        ret.insert(k.to_string(), b64);
    }
    Ok(ret)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TxOutputDef {
    // message fields
    #[serde(serialize_with = "serialize_bytes")]
    pub amount: ::std::vec::Vec<u8>,
    #[serde(serialize_with = "serialize_bytes")]
    pub to_addr: ::std::vec::Vec<u8>,
    #[serde(skip_serializing_if = "is_zero")]
    pub frozen_height: i64,
}

impl From<&xchain::TxOutput> for TxOutputDef {
    fn from(to: &xchain::TxOutput) -> Self {
        TxOutputDef {
            amount: to.amount.clone(),
            to_addr: to.to_addr.clone(),
            frozen_height: to.frozen_height,
        }
    }
}

#[allow(non_snake_case)]
#[derive(Serialize, Deserialize, Debug)]
pub struct SignatureInfoDef {
    // message fields
    pub PublicKey: ::std::string::String,
    #[serde(serialize_with = "serialize_bytes")]
    pub Sign: ::std::vec::Vec<u8>,
}

impl From<&xchain::SignatureInfo> for SignatureInfoDef {
    fn from(si: &xchain::SignatureInfo) -> Self {
        SignatureInfoDef {
            PublicKey: si.PublicKey.to_owned(),
            Sign: si.Sign.clone(),
        }
    }
}

#[allow(non_snake_case)]
pub struct TransactionDef {
    pub tx_inputs: Vec<xchain::TxInput>,
    pub tx_outputs: Vec<TxOutputDef>,
    pub desc: ::std::vec::Vec<u8>,
    pub nonce: ::std::string::String,
    pub timestamp: i64,
    pub version: i32,

    pub tx_inputs_ext: Vec<xchain::TxInputExt>,
    pub tx_outputs_ext: Vec<xchain::TxOutputExt>,

    pub contract_requests: Vec<xchain::InvokeRequest>,
    pub initiator: ::std::string::String,
    pub auth_require: Vec<::std::string::String>,

    //the only difference part
    pub initiator_signs: Vec<SignatureInfoDef>,
    pub auth_require_signs: Vec<SignatureInfoDef>,
    pub xuper_sign: Option<xchain::XuperSignature>,

    pub coinbase: bool,
    pub autogen: bool,

    pub HD_info: Option<xchain::HDInfo>,
    pub include_signes: bool,
}

impl TransactionDef {
    fn serialize(&self) -> Result<String> {
        let mut j = String::new();
        for ti in &self.tx_inputs {
            encode_bytes(&ti.ref_txid, &mut j)?;
            let s = serde_json::to_string(&ti.ref_offset)?;
            j.push_str(&s);
            j.push('\n');
            encode_bytes(&ti.from_addr, &mut j)?;
            encode_bytes(&ti.amount, &mut j)?;
            let s = serde_json::to_string(&ti.frozen_height)?;
            j.push_str(&s);
            j.push('\n');
        }

        let s = serde_json::to_string(&self.tx_outputs)?;
        j.push_str(&s);
        j.push('\n');

        encode_bytes(&self.desc, &mut j)?;

        let s = serde_json::to_string(&self.nonce)?;
        j.push_str(&s);
        j.push('\n');

        let s = serde_json::to_string(&self.timestamp)?;
        j.push_str(&s);
        j.push('\n');

        let s = serde_json::to_string(&self.version)?;
        j.push_str(&s);
        j.push('\n');

        for tie in &self.tx_inputs_ext {
            let ti = serde_json::to_string(&tie.bucket)?;
            j.push_str(&ti);
            j.push('\n');

            encode_bytes(&tie.key, &mut j)?;
            encode_bytes(&tie.ref_txid, &mut j)?;

            let ti = serde_json::to_string(&tie.ref_offset)?;
            j.push_str(&ti);
            j.push('\n');
        }

        for toe in &self.tx_outputs_ext {
            let ti = serde_json::to_string(&toe.bucket)?;
            j.push_str(&ti);
            j.push('\n');
            encode_bytes(&toe.key, &mut j)?;
            encode_bytes(&toe.value, &mut j)?;
        }

        // map 按照key的字母顺序排列
        encode_array::<xchain::InvokeRequest>(&self.contract_requests, &mut j)?;

        let s = serde_json::to_string(&self.initiator)?;
        j.push_str(&s);
        j.push('\n');

        encode_array::<String>(&self.auth_require, &mut j)?;

        if self.include_signes {
            encode_array::<SignatureInfoDef>(&self.initiator_signs, &mut j)?;
            encode_array::<SignatureInfoDef>(&self.auth_require_signs, &mut j)?;

            if self.xuper_sign.is_some() {
                //TODO BUG
                let s = serde_json::to_string(&self.auth_require_signs)?;
                j.push_str(&s);
                j.push('\n');
            }
        }

        let s = serde_json::to_string(&self.coinbase)?;
        j.push_str(&s);
        j.push('\n');

        let s = serde_json::to_string(&self.autogen)?;
        j.push_str(&s);
        j.push('\n');

        if self.version > 2 {
            let s = serde_json::to_string(&self.HD_info)?;
            j.push_str(&s);
            j.push('\n');
        }

        Ok(j)
    }
}

impl From<&xchain::Transaction> for TransactionDef {
    fn from(tx: &xchain::Transaction) -> Self {
        TransactionDef {
            include_signes: false,
            tx_inputs: tx.tx_inputs.clone().into_vec(),
            tx_outputs: tx
                .tx_outputs
                .clone()
                .into_vec()
                .iter()
                .map(|x| TxOutputDef::from(x))
                .collect(),
            desc: tx.desc.clone(),
            nonce: tx.nonce.to_owned(),
            timestamp: tx.timestamp,
            version: tx.version,
            tx_inputs_ext: tx.tx_inputs_ext.clone().into_vec(),
            tx_outputs_ext: tx.tx_outputs_ext.clone().into_vec(),
            contract_requests: tx.contract_requests.clone().into_vec(),
            initiator: tx.initiator.to_owned(),
            auth_require: tx.auth_require.clone().into_vec(),
            initiator_signs: tx
                .initiator_signs
                .clone()
                .into_vec()
                .iter()
                .map(|x| SignatureInfoDef::from(x))
                .collect(),
            auth_require_signs: tx
                .auth_require_signs
                .clone()
                .into_vec()
                .iter()
                .map(|x| SignatureInfoDef::from(x))
                .collect(),
            xuper_sign: tx.xuper_sign.clone().into_option(),
            coinbase: tx.coinbase,
            autogen: tx.autogen,
            HD_info: tx.HD_info.clone().into_option(),
        }
    }
}

pub fn make_tx_digest_hash(tx: &xchain::Transaction) -> Result<Vec<u8>> {
    let d = TransactionDef::from(tx);
    let d = d.serialize()?;
    //notice: cryptos  do digest once default
    Ok(xchain_crypto::hash::hash::sha256(d.as_bytes()))
}

pub fn make_transaction_id(tx: &xchain::Transaction) -> Result<Vec<u8>> {
    let mut d = TransactionDef::from(tx);
    d.include_signes = true;
    let d = d.serialize()?;
    Ok(xchain_crypto::hash::hash::double_sha256(d.as_bytes()))
}
