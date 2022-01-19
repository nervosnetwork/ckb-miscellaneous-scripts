#![allow(unused_imports)]
#![allow(dead_code)]

use ckb_crypto::secp::Generator;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::{bytes::Bytes, bytes::BytesMut, packed::WitnessArgs, prelude::*, H256};
use lazy_static::lazy_static;
use rand::prelude::*;
use rand::{thread_rng, Rng, SeedableRng};

use blst::min_pk::*;
use blst::*;

use misc::{
    blake160, build_resolved_tx, debug_printer, gen_tx, gen_tx_with_grouped_args, gen_witness_lock,
    sign_tx, sign_tx_by_input_group, BlstData, DummyDataLoader, TestConfig, TestScheme,
    ERROR_BLST_VERIFY_FAILED, ERROR_ENCODING, ERROR_PUBKEY_BLAKE160_HASH, ERROR_WITNESS_SIZE,
    IDENTITY_FLAGS_BLS12_381, MAX_CYCLES,
};

mod misc;

lazy_static! {}

#[test]
fn test_sighash_all_unlock() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BLS12_381);

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
    // println!("Consume cycles: {} M", cycles / 1024 / 1024);
}

#[test]
fn test_sighash_all_unlock_failed() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BLS12_381);
    config.scheme = TestScheme::WrongSignature;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_BLST_VERIFY_FAILED).input_lock_script(0),
    );
}

#[test]
fn test_sighash_all_unlock_failed_wrong_pubkey() {
    let mut data_loader = DummyDataLoader::new();

    let mut config = TestConfig::new(IDENTITY_FLAGS_BLS12_381);
    config.scheme = TestScheme::WrongPubKey;

    let tx = gen_tx(&mut data_loader, &mut config);
    let tx = sign_tx(&mut data_loader, tx, &mut config);
    let resolved_tx = build_resolved_tx(&data_loader, &tx);

    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(ERROR_BLST_VERIFY_FAILED).input_lock_script(0),
    );
}

#[test]
fn test_blst() {
    let bd = BlstData::new();
    let msg: Vec<u8> = vec![1, 2, 3];
    let sig = bd.sign(msg.as_slice());
    let res = bd.verify(msg.as_slice(), &sig);
    assert!(res);

    let pk = bd.get_pubkey();
    assert_eq!(pk.len(), 48);
    assert_eq!(sig.len(), 96);
}
