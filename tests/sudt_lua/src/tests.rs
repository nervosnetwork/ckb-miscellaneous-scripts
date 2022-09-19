use p256::ecdsa::signature::{Signature, Signer};

use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::{
    bytes::BufMut,
    bytes::Bytes,
    bytes::BytesMut,
    core::{EpochExt, HeaderView, TransactionView},
    packed::{self, Byte32},
    prelude::*,
};
use lazy_static::lazy_static;
use p256::ecdsa::{SigningKey, VerifyingKey};
use std::collections::HashMap;

use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::core::hardfork::HardForkSwitch;
use ckb_types::{
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, EpochNumberWithFraction, ScriptHashType, TransactionBuilder,
    },
    packed::{CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder},
};
use hex_literal::hex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const LOCK_WITNESS_SIZE: usize = 128;

const ERROR_AMOUNT: i8 = -7;

static LARGER_AMOUNT: [u8; 16] = [
    0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8,
    0x42u8, 0x43u8, 0x42u8, 0x43u8,
];

static SMALLER_AMOUNT: [u8; 16] = [
    0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8, 0x43u8, 0x42u8,
    0x43u8, 0x42u8, 0x43u8, 0x42u8,
];

lazy_static! {
    pub static ref LUA_LOADER_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../deps/ckb-lua/build/lua-loader")[..]);
    pub static ref SECP256R1_BLAKE160_SIGHASH_ALL_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256r1_blake160_sighash_all")[..]);
    pub static ref SUDT_LUA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../deps/ckb-lua/contracts/sudt.lua")[..]);
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
            .map(|(_, data)| CellOutput::calc_data_hash(data))
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

pub fn sign_txs(tx: TransactionView, keys: &[SigningKey]) -> TransactionView {
    let mut tx = tx;
    for (i, key) in keys.iter().enumerate() {
        tx = sign_tx_by_input_group(tx, key, i, 1)
    }
    tx
}

pub fn get_blake2_hash_for_input_group(
    tx: TransactionView,
    start_index: usize,
    wintess_num: usize,
) -> [u8; 32] {
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx.hash().raw_data());
    // digest the first witness
    let witness = WitnessArgs::new_unchecked(tx.witnesses().get(start_index).unwrap().unpack());
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(LOCK_WITNESS_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness.as_builder().lock(Some(zero_lock).pack()).build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    dbg!(&tx.witnesses());
    ((start_index + 1)..(start_index + wintess_num)).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);
    message
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
                get_blake2_hash_for_input_group(tx.clone(), i, len);
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock: Bytes = {
                    let mut buf = Vec::new();
                    buf.resize(LOCK_WITNESS_SIZE, 0);
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

                let pk_point = key.verifying_key().to_encoded_point(false);
                let pk_bytes = &pk_point.as_bytes()[1..];

                let sig = key.sign(&message);
                let sig_bytes = sig.as_bytes();

                let mut buf = BytesMut::with_capacity(pk_bytes.len() + sig_bytes.len());
                buf.put(pk_bytes);
                buf.put(sig_bytes);
                let bytes = buf.freeze();

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

fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let _str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    // println!("{:?}: {}", str, msg);
    print!("{}", msg);
}

fn get_pk_hash(pubkey: &VerifyingKey) -> Bytes {
    blake160(&pubkey.to_encoded_point(false).as_bytes()[1..])
}

fn gen_tx(
    dummy: &mut DummyDataLoader,
    arguments: &[GenerateTransactionArgument],
) -> TransactionView {
    let mut rng = <StdRng as SeedableRng>::from_seed([42u8; 32]);
    gen_tx_with_grouped_args(dummy, arguments, &mut rng)
}

fn get_random_out_point<R: Rng>(rng: &mut R) -> OutPoint {
    let contract_tx_hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(contract_tx_hash, 0)
}

fn create_cell(
    dummy: &mut DummyDataLoader,
    out_point: &OutPoint,
    content: &Bytes,
) -> packed::Byte32 {
    let cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(content.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let cell_data_hash = CellOutput::calc_data_hash(content);
    dbg!(out_point, dummy.cells.keys());
    dummy
        .cells
        .insert(out_point.clone(), (cell, content.clone()));
    dbg!(out_point, dummy.cells.keys());
    cell_data_hash
}

fn get_lua_type_script_args(hash: packed::Byte32) -> Bytes {
    let lua_loader_arguments: [u8; 2] = [0; 2];
    let lua_loader_arguments = lua_loader_arguments.as_slice();
    let hash = hash.as_slice();
    let hash_type: packed::Byte = ScriptHashType::Data1.into();
    let hash_type = hash_type.as_slice();
    let owner_pk_hash = get_owner_lock_hash();
    let owner_pk_hash = owner_pk_hash.as_ref();
    let mut buf = BytesMut::with_capacity(
        lua_loader_arguments.len() + hash.len() + hash_type.len() + owner_pk_hash.len(),
    );
    buf.put(lua_loader_arguments);
    buf.put(hash);
    buf.put(hash_type);
    buf.put(owner_pk_hash);
    buf.freeze()
}

// For simplicity, we don't use grouped inputs/outputs here
struct GenerateTransactionArgument {
    sk: SigningKey,
    input_amount: Option<[u8; 16]>,
    output_amount: Option<[u8; 16]>,
}

const AMOUNT_ZERO: [u8; 16] = [0; 16];

fn gen_tx_with_grouped_args<R: Rng>(
    dummy: &mut DummyDataLoader,
    arguments: &[GenerateTransactionArgument],
    rng: &mut R,
) -> TransactionView {
    let lua_binary_out_point = get_random_out_point(rng);
    let lua_binary_cell_data_hash = create_cell(dummy, &lua_binary_out_point, &LUA_LOADER_BIN);

    let lua_script_out_point = get_random_out_point(rng);
    let lua_script_cell_data_hash = create_cell(dummy, &lua_script_out_point, &SUDT_LUA_BIN);

    let lock_script_out_point = get_random_out_point(rng);
    let lock_script_cell_data_hash = create_cell(
        dummy,
        &lock_script_out_point,
        &SECP256R1_BLAKE160_SIGHASH_ALL_BIN,
    );

    dbg!(
        &lua_binary_cell_data_hash,
        &lua_binary_out_point,
        &lua_script_cell_data_hash,
        &lua_script_out_point,
        &lock_script_cell_data_hash,
        &lock_script_out_point
    );

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(lua_binary_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(lua_script_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(lock_script_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    for argument in arguments {
        let pk_hash = get_pk_hash(&argument.sk.verifying_key());
        let previous_out_point = get_random_out_point(rng);
        let type_script = Script::new_builder()
            .args(get_lua_type_script_args(lua_script_cell_data_hash.clone()).pack())
            .code_hash(lua_binary_cell_data_hash.clone())
            .hash_type(ScriptHashType::Data1.into())
            .build();
        let lock_script = Script::new_builder()
            .args(pk_hash.pack())
            .code_hash(lock_script_cell_data_hash.clone())
            .hash_type(ScriptHashType::Data1.into())
            .build();
        dbg!(&type_script, &dummy.cells.keys());
        let previous_output_cell = CellOutput::new_builder()
            .capacity(dummy_capacity.pack())
            .lock(lock_script.clone())
            .type_(Some(type_script.clone()).pack())
            .build();
        // The number is in little endian format.
        dummy.cells.insert(
            previous_out_point.clone(),
            (
                previous_output_cell.clone(),
                Bytes::copy_from_slice(&argument.input_amount.unwrap_or(AMOUNT_ZERO)),
            ),
        );
        dbg!(&dummy.cells.keys());
        let mut random_extra_witness = [0u8; 32];
        rng.fill(&mut random_extra_witness);
        let witness_args = WitnessArgsBuilder::default()
            .output_type(Some(Bytes::from(random_extra_witness.to_vec())).pack())
            .build();
        dbg!(&tx_builder);
        dbg!(&random_extra_witness);
        let mut output_data = [0u8; 16];
        output_data[0] = 0x43u8;
        output_data[1] = 0x42u8;
        tx_builder = tx_builder
            .input(CellInput::new(previous_out_point, 0))
            .output(
                CellOutput::new_builder()
                    .capacity(dummy_capacity.pack())
                    .lock(lock_script.clone())
                    .type_(Some(type_script).pack())
                    .build(),
            )
            .output_data(
                Bytes::copy_from_slice(&argument.output_amount.unwrap_or(AMOUNT_ZERO)).pack(),
            )
            .witness(witness_args.as_bytes().pack());
        dbg!(&tx_builder);
    }

    dbg!(&tx_builder);
    tx_builder.build()
}

pub fn gen_tx_env() -> TxVerifyEnv {
    let epoch = EpochNumberWithFraction::new(300, 0, 1);
    let header = HeaderView::new_advanced_builder()
        .epoch(epoch.pack())
        .build();
    TxVerifyEnv::new_commit(&header)
}

pub fn gen_consensus() -> Consensus {
    let hardfork_switch = HardForkSwitch::new_without_any_enabled()
        .as_builder()
        .rfc_0032(200)
        .build()
        .unwrap();
    ConsensusBuilder::default()
        .hardfork_switch(hardfork_switch)
        .build()
}

fn build_resolved_tx(data_loader: &DummyDataLoader, tx: &TransactionView) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|deps_out_point| {
            dbg!(&deps_out_point);
            dbg!(&data_loader.cells.keys());
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}

fn get_owner_signing_key() -> SigningKey {
    let x = &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622bdeadbeef");
    SigningKey::from_bytes(x).unwrap()
}

fn get_owner_lock_hash() -> Bytes {
    // Dumped from ckb ckb.load_cell_by_field(index, ckb.SOURCE_INPUT, ckb.CELL_FIELD_LOCK_HASH)
    static OWNER_LOCK_HASH: [u8; 32] =
        hex!("854188d34c6b65bf2307cceffd42ab0cfe85b6c8dc8fd7aa6a7a621ce982e2bf");
    Bytes::from_static(&OWNER_LOCK_HASH)
}

fn get_sample_signing_key() -> SigningKey {
    let x = &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");

    SigningKey::from_bytes(x).unwrap()
}

fn get_random_signing_key<
    RNG: p256::elliptic_curve::rand_core::CryptoRng + p256::elliptic_curve::rand_core::RngCore,
>(
    rng: RNG,
) -> SigningKey {
    SigningKey::random(rng)
}

fn get_random_signing_keys(n: usize) -> Vec<SigningKey> {
    let rng = p256::elliptic_curve::rand_core::OsRng::default();
    (0..n).map(|_| get_random_signing_key(rng)).collect()
}

#[test]
fn test_simple_user_defined_token() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_sample_signing_key();
    let tx = gen_tx(
        &mut data_loader,
        &[GenerateTransactionArgument {
            sk: privkey.clone(),
            input_amount: Some(LARGER_AMOUNT),
            output_amount: Some(SMALLER_AMOUNT),
        }],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    println!("{}", resolved_tx.transaction.data());
    dbg!(&resolved_tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_user_defined_token2() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_random_signing_keys(2);
    let mut input_data = [0u8; 16];
    input_data[0] = 0x42u8;
    input_data[1] = 0x43u8;
    let mut output_data = [0u8; 16];
    output_data[0] = 0x43u8;
    output_data[1] = 0x42u8;
    let tx = gen_tx(
        &mut data_loader,
        &[
            GenerateTransactionArgument {
                sk: privkey[0].clone(),
                input_amount: Some(LARGER_AMOUNT),
                output_amount: Some(SMALLER_AMOUNT),
            },
            GenerateTransactionArgument {
                sk: privkey[1].clone(),
                input_amount: Some(SMALLER_AMOUNT),
                output_amount: Some(LARGER_AMOUNT),
            },
        ],
    );
    let tx = sign_txs(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    println!("{}", resolved_tx.transaction.data());
    dbg!(&resolved_tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_owner_mint_tokens() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_owner_signing_key();
    let tx = gen_tx(
        &mut data_loader,
        &[GenerateTransactionArgument {
            sk: privkey.clone(),
            input_amount: None,
            output_amount: Some(LARGER_AMOUNT),
        }],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    println!("{}", resolved_tx.transaction.data());
    dbg!(&resolved_tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_non_owner_mint_tokens() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_sample_signing_key();
    let tx = gen_tx(
        &mut data_loader,
        &[GenerateTransactionArgument {
            sk: privkey.clone(),
            input_amount: None,
            output_amount: Some(LARGER_AMOUNT),
        }],
    );
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    println!("{}", resolved_tx.transaction.data());
    dbg!(&resolved_tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier =
        TransactionScriptsVerifier::new(&resolved_tx, &consensus, &data_loader, &tx_env);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    let error = format!("error code {}", ERROR_AMOUNT);
    dbg!(&verify_result.clone().unwrap_err().to_string());
    assert!(verify_result.unwrap_err().to_string().contains(&error));
}
