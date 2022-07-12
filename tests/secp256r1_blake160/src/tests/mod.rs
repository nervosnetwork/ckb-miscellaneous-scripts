mod secp256r1_blake160_sighash_all;

use p256::ecdsa::{
    signature::{Signature, Signer},
    SigningKey,
};

use bytes::{BufMut, BytesMut};

use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::Bytes,
    core::{EpochExt, HeaderView, TransactionView},
    packed::{self, Byte32, CellOutput, OutPoint, WitnessArgs},
    prelude::*,
};
use lazy_static::lazy_static;
use std::collections::HashMap;

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

lazy_static! {
    pub static ref SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../../build/secp256r1_blake160_sighash_all")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../../build/secp256k1_data")[..]);
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, Bytes)>,
    pub headers: HashMap<Byte32, HeaderView>,
    pub epoches: HashMap<Byte32, EpochExt>,
}

impl DummyDataLoader {
    fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    fn get_cell_data(&self, out_point: &OutPoint) -> Option<ckb_types::bytes::Bytes> {
        self.cells.get(out_point).map(|(_, data)| data.clone())
    }

    fn get_cell_data_hash(&self, out_point: &OutPoint) -> Option<Byte32> {
        self.cells
            .get(out_point)
            .map(|(_, data)| CellOutput::calc_data_hash(&data))
    }
}

impl HeaderProvider for DummyDataLoader {
    // load header
    fn get_header(&self, block_hash: &Byte32) -> Option<HeaderView> {
        self.headers.get(block_hash).cloned()
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    let hash: [u8; 32] = ckb_hash::blake2b_256(message);
    Bytes::copy_from_slice(&hash[0..20])
}

pub fn sign_tx(tx: TransactionView, key: &SigningKey) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    sign_tx_by_input_group(tx, key, 0, witnesses_len)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    key: &SigningKey,
    begin_index: usize,
    len: usize,
) -> TransactionView {
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(SIGNATURE_SIZE, 0);
                    buf.into()
                };
                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let sig = key.sign(&message);
                let sig_bytes = sig.as_bytes();

                let verifying_key = key.verifying_key().to_encoded_point(false);
                let verifying_key_bytes = &verifying_key.as_bytes()[1..];

                let mut buf = BytesMut::with_capacity(verifying_key_bytes.len() + sig_bytes.len());
                buf.put(verifying_key_bytes);
                buf.put(sig_bytes);
                let bytes = buf.freeze();
                dbg!(&verifying_key_bytes, sig_bytes, &bytes);
                println!(
                    "verifying_key: len({}) {:02X?}",
                    verifying_key_bytes.len(),
                    verifying_key_bytes
                );
                println!("bytes: len({}) {:02X?}", bytes.len(), bytes);

                witness
                    .as_builder()
                    .lock(Some(bytes).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}
