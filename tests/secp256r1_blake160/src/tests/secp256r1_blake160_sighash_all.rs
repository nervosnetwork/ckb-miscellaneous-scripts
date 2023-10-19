use super::{
    blake160, sign_tx, sign_tx_by_input_group, DummyDataLoader, MAX_CYCLES, SIGHASH_ALL_BIN,
};
use ckb_chain_spec::consensus::{Consensus, ConsensusBuilder};
use p256::ecdsa::{SigningKey, VerifyingKey};

use ckb_script::{TransactionScriptsVerifier, TxVerifyEnv};
use ckb_types::core::hardfork::HardForks;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, EpochNumberWithFraction, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{
        Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder,
    },
    prelude::*,
};
use hex_literal::hex;
use rand::rngs::StdRng;
use rand::{thread_rng, Rng, SeedableRng};
use std::sync::Arc;

const ERROR_SECP_VERIFICATION: i8 = -12;
const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;

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

fn gen_tx(dummy: &mut DummyDataLoader, lock_args: Bytes) -> TransactionView {
    let mut rng = <StdRng as SeedableRng>::from_seed([42u8; 32]);
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], &mut rng)
}

fn gen_tx_with_grouped_args<R: Rng>(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    rng: &mut R,
) -> TransactionView {
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash, 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SIGHASH_ALL_BIN.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&SIGHASH_ALL_BIN);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, SIGHASH_ALL_BIN.clone()),
    );
    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    for (args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [0u8; 32];
                rng.fill(&mut buf);
                buf.pack()
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra_witness = [0u8; 32];
            rng.fill(&mut random_extra_witness);
            let witness_args = WitnessArgsBuilder::default()
                .output_type(Some(Bytes::from(random_extra_witness.to_vec())).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

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
    let mut hardfork_switch = HardForks::new_mirana();
    hardfork_switch.ckb2021 = hardfork_switch
        .ckb2021
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

fn get_sample_signing_key() -> SigningKey {
    let x = &hex!("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
    let sk = SigningKey::from_bytes(x).unwrap();
    sk
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
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_sample_signing_key();
    let pubkey = privkey.verifying_key();
    let tx = gen_tx(&mut data_loader, get_pk_hash(&pubkey));
    let tx = sign_tx(tx, &privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let mut verifier = TransactionScriptsVerifier::new(
        Arc::new(resolved_tx),
        data_loader,
        Arc::new(consensus),
        Arc::new(tx_env),
    );
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_sighash_all_with_extra_witness_unlock() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_sample_signing_key();
    let pubkey = privkey.verifying_key();
    let tx = gen_tx(&mut data_loader, get_pk_hash(&pubkey));
    let extract_witness = vec![1, 2, 3, 4];
    let tx = tx
        .as_advanced_builder()
        .set_witnesses(vec![WitnessArgs::new_builder()
            .output_type(Some(Bytes::from(extract_witness)).pack())
            .build()
            .as_bytes()
            .pack()])
        .build();
    {
        let tx = sign_tx(tx.clone(), &privkey);
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let verify_result = TransactionScriptsVerifier::new(
            Arc::new(resolved_tx),
            data_loader.clone(),
            Arc::new(consensus),
            Arc::new(tx_env),
        )
        .verify(MAX_CYCLES);
        verify_result.expect("pass verification");
    }
    {
        let tx = sign_tx(tx, &privkey);
        let wrong_witness = tx
            .witnesses()
            .get(0)
            .map(|w| {
                WitnessArgs::new_unchecked(w.unpack())
                    .as_builder()
                    .output_type(Some(Bytes::from(vec![0])).pack())
                    .build()
            })
            .unwrap();
        let tx = tx
            .as_advanced_builder()
            .set_witnesses(vec![wrong_witness.as_bytes().pack()])
            .build();
        let resolved_tx = build_resolved_tx(&data_loader, &tx);
        let consensus = gen_consensus();
        let tx_env = gen_tx_env();
        let verify_result = TransactionScriptsVerifier::new(
            Arc::new(resolved_tx),
            data_loader.clone(),
            Arc::new(consensus),
            Arc::new(tx_env),
        )
        .verify(MAX_CYCLES);
        assert!(verify_result.is_err());
        let error = format!("error code {}", ERROR_SECP_VERIFICATION);
        dbg!(&verify_result.clone().unwrap_err().to_string());
        assert!(verify_result.unwrap_err().to_string().contains(&error));
    }
}

#[test]
fn test_sighash_all_with_2_different_inputs_unlock() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let privkeys = get_random_signing_keys(2);
    // key1
    let privkey = &privkeys[0];
    let pubkey = privkey.verifying_key();
    // key2
    let privkey2 = &privkeys[1];
    let pubkey2 = privkey2.verifying_key();

    // sign with 2 keys
    let tx = gen_tx_with_grouped_args(
        &mut data_loader,
        vec![(get_pk_hash(&pubkey), 2), (get_pk_hash(&pubkey2), 2)],
        &mut rng,
    );
    let tx = sign_tx_by_input_group(tx, &privkey, 0, 2);
    let tx = sign_tx_by_input_group(tx, &privkey2, 2, 2);

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let verify_result = TransactionScriptsVerifier::new(
        Arc::new(resolved_tx),
        data_loader,
        Arc::new(consensus),
        Arc::new(tx_env),
    )
    .verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_signing_with_wrong_key() {
    let mut data_loader = DummyDataLoader::new();
    let privkey = get_sample_signing_key();
    let pubkey = privkey.verifying_key();
    let tx = gen_tx(&mut data_loader, get_pk_hash(&pubkey));
    let wrong_privkey = SigningKey::from_bytes(&hex!(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6722"
    ))
    .unwrap();
    let tx = sign_tx(tx, &wrong_privkey);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let consensus = gen_consensus();
    let tx_env = gen_tx_env();
    let verify_result = TransactionScriptsVerifier::new(
        Arc::new(resolved_tx),
        data_loader,
        Arc::new(consensus),
        Arc::new(tx_env),
    )
    .verify(MAX_CYCLES);
    assert!(verify_result.is_err());
    let error = format!("error code {}", ERROR_PUBKEY_BLAKE160_HASH);
    assert!(verify_result.unwrap_err().to_string().contains(&error));
}
