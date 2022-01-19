use std::collections::HashMap;

//ddd 1. useless lib
use blst::min_pk::*;
use blst::*;
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::bytes::{BufMut, BytesMut};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, HeaderView, ScriptHashType, TransactionBuilder, TransactionView,
    },
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
};
use lazy_static::lazy_static;
use rand::prelude::*;
use rand::Rng;

//ddd 2. need write one
use blst_test::rc_lock::RcLockWitnessLock;

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub const MAX_CYCLES: u64 = std::u64::MAX;

//ddd 3. get secp256r1 signature size
pub const SIGNATURE_SIZE: usize = 144;

// errors
pub const ERROR_ENCODING: i8 = -2;
pub const ERROR_WITNESS_SIZE: i8 = -22;
pub const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;
pub const ERROR_BLST_VERIFY_FAILED: i8 = 72;
pub const ERROR_OUTPUT_AMOUNT_NOT_ENOUGH: i8 = -42;
pub const ERROR_NO_PAIR: i8 = -44;
pub const ERROR_DUPLICATED_INPUTS: i8 = -45;
pub const ERROR_DUPLICATED_OUTPUTS: i8 = -46;
pub const ERROR_LOCK_SCRIPT_HASH_NOT_FOUND: i8 = 70;
pub const ERROR_NOT_ON_WHITE_LIST: i8 = 59;
pub const ERROR_NO_WHITE_LIST: i8 = 83;
pub const ERROR_ON_BLACK_LIST: i8 = 57;
pub const ERROR_RCE_EMERGENCY_HALT: i8 = 54;

//ddd 4. change to ec_secp256r1_core
lazy_static! {
    pub static ref BLST_LOCK: Bytes =
        Bytes::from(&include_bytes!("../../../build/bls12_381_sighash_all")[..]);
}

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        Pack::pack(&buf)
    };
    OutPoint::new(hash, 0)
}

//
// deploy "bin" to cell, then build a script to point it.
//
// it can:
// * build lock script, set is_type to false
// * build type script, set is_type to true
// * build type script without upgrading, set is_type to false
// * build extension script, set is_type to true
// * build extension script without upgrading, set is_type to false
// * build RCE cell, is_type = true. Only the Script.code_hash is kept for further use.
//   when in this case, to make "args" passed in unique
fn _build_script(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    is_type: bool,
    bin: &Bytes,
    args: Bytes,
) -> (TransactionBuilder, Script) {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);

    let type_script_in_code = {
        // this args can be anything
        let args = vec![0u8; 32];
        Script::new_builder()
            .args(args.pack())
            .code_hash(hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .build()
    };

    // it not needed to set "type script" when is_type is false
    let capacity = bin.len() as u64;
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let out_point = &OutPoint::new(hash.pack(), 0);

    dummy.cells.insert(out_point.clone(), (cell, bin.clone()));

    let tx_builder = tx_builder.cell_dep(
        CellDep::new_builder()
            .out_point(out_point.clone())
            .dep_type(DepType::Code.into())
            .build(),
    );
    let code_hash = if is_type {
        ckb_hash::blake2b_256(type_script_in_code.as_slice())
    } else {
        ckb_hash::blake2b_256(bin)
    };
    let hash_type = if is_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    };

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();

    (tx_builder, script)
}

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, ckb_types::bytes::Bytes)>,
}

impl DummyDataLoader {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<ckb_types::bytes::Bytes> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| data.clone())
        })
    }

    fn load_cell_data_hash(&self, cell: &CellMeta) -> Option<Byte32> {
        self.load_cell_data(cell)
            .map(|e| CellOutput::calc_data_hash(&e))
    }

    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<ckb_types::bytes::Bytes> {
        None
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        None
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, _hash: &Byte32) -> Option<HeaderView> {
        None
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    let r = ckb_hash::blake2b_256(message);
    Bytes::copy_from_slice(&r[..20])
}

pub fn sign_tx(
    _dummy: &mut DummyDataLoader,
    tx: TransactionView,
    config: &mut TestConfig,
) -> TransactionView {
    let len = tx.witnesses().len();
    sign_tx_by_input_group(tx, 0, len, config)
}

//ddd 5.can't achieve -- line229
pub fn sign_tx_by_input_group(
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &TestConfig,
) -> TransactionView {
    let identity = config.id.to_identity();
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
                let zero_lock = gen_zero_witness_lock(&identity);

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

                let mut sig = config.blst_data.sign2(&message[..]);
                if config.scheme == TestScheme::WrongSignature {
                    sig[sig.len() - 1] ^= 0x1;
                }
                if config.scheme == TestScheme::WrongPubKey {
                    sig[0] ^= 0x1;
                }

                let sig_bytes = Bytes::copy_from_slice(&sig[..]);
                let witness_lock = gen_witness_lock(sig_bytes, &identity);
                witness
                    .as_builder()
                    .lock(Some(witness_lock).pack())
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
    if config.scheme2 == TestScheme2::NoWitness {
        signed_witnesses.clear();
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn gen_tx(dummy: &mut DummyDataLoader, config: &mut TestConfig) -> TransactionView {
    let lock_args = config.gen_args();
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config)
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    _config: &mut TestConfig,
) -> TransactionView {
    let mut rng = thread_rng();
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    // ddd 6. change to secp256r1
    let blst_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(BLST_LOCK.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&BLST_LOCK);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (blst_cell, BLST_LOCK.clone()),
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
            let mut random_extra_witness = Vec::<u8>::new();
            let witness_len = 32;
            random_extra_witness.resize(witness_len, 0);
            rng.fill(&mut random_extra_witness[..]);

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::copy_from_slice(&random_extra_witness[..])).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
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

pub fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
}

//ddd 7. change identity flags
pub const IDENTITY_FLAGS_PUBKEY_HASH: u8 = 0;
pub const IDENTITY_FLAGS_OWNER_LOCK: u8 = 1;
pub const IDENTITY_FLAGS_BLS12_381: u8 = 15;

pub struct Identity {
    pub flags: u8,
    pub blake160: Bytes,
}

impl Identity {
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
    //ddd 8. replace blst_test
    pub fn to_identity(&self) -> blst_test::rc_lock::Identity {
        let mut ret: [u8; 21] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        blst_test::rc_lock::Identity::from_slice(&ret[..]).unwrap()
    }
}

//ddd 9. below???
pub struct TestConfig {
    pub id: Identity,
    pub use_rc: bool,
    pub scheme: TestScheme,
    pub scheme2: TestScheme2,
    pub rc_root: Bytes,
    pub proofs: Vec<Vec<u8>>,
    pub proof_masks: Vec<u8>,
    pub blst_data: BlstData,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme {
    None,
    LongWitness,

    OnWhiteList,
    NotOnWhiteList,
    OnlyInputOnWhiteList,
    OnlyOutputOnWhiteList,
    BothOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,

    OwnerLockMismatched,
    OwnerLockWithoutWitness,
    WrongSignature,
    WrongPubKey,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme2 {
    None,
    NoWitness,
}

impl TestConfig {
    pub fn new(flags: u8) -> TestConfig {
        let blst_data = BlstData::new();
        let pk = blst_data.get_pubkey();
        let blake160 = blake160(&pk[..]);

        TestConfig {
            id: Identity { flags, blake160 },
            use_rc: false,
            rc_root: Default::default(),
            scheme: TestScheme::None,
            scheme2: TestScheme2::None,
            proofs: Default::default(),
            proof_masks: Default::default(),
            blst_data,
        }
    }

    pub fn set_scheme(&mut self, scheme: TestScheme) {
        self.scheme = scheme;
    }

    pub fn gen_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);
        if self.use_rc {
            bytes.resize(21, 0);
            bytes.put(self.rc_root.as_ref());
        } else {
            bytes.put_u8(self.id.flags);
            bytes.put(self.id.blake160.as_ref());
        }
        bytes.freeze()
    }

    pub fn is_owner_lock(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_OWNER_LOCK
    }
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_PUBKEY_HASH
    }
    pub fn is_rc(&self) -> bool {
        self.use_rc
    }
}

pub fn gen_witness_lock(sig: Bytes, _identity: &blst_test::rc_lock::Identity) -> Bytes {
    let builder = RcLockWitnessLock::new_builder();

    let builder = builder.signature(Some(sig).pack());

    builder.build().as_bytes()
}

pub fn gen_zero_witness_lock(identity: &blst_test::rc_lock::Identity) -> Bytes {
    let mut zero = BytesMut::new();
    zero.resize(SIGNATURE_SIZE, 0);
    let witness_lock = gen_witness_lock(zero.freeze(), identity);

    let mut res = BytesMut::new();
    res.resize(witness_lock.len(), 0);
    res.freeze()
}

pub struct BlstData {
    sk: SecretKey,
    pk: PublicKey,
    dst: Vec<u8>,
}

impl BlstData {
    pub fn new() -> BlstData {
        let mut rng = thread_rng();
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        let pk = sk.sk_to_pk();
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
            .as_bytes()
            .to_owned();
        BlstData { sk, pk, dst }
    }
    pub fn sign(&self, msg: &[u8]) -> [u8; 96] {
        let sig = self.sk.sign(&msg, &self.dst, &[]);
        sig.compress()
    }
    pub fn sign2(&self, msg: &[u8]) -> [u8; 144] {
        let mut res = [0u8; 144];
        let pk = self.pk.compress();
        let sig = self.sign(msg);
        &res[0..48].copy_from_slice(&pk[..]);
        &res[48..].copy_from_slice(&sig[..]);
        res
    }

    pub fn verify(&self, msg: &[u8], sig: &[u8; 96]) -> bool {
        let sig = Signature::from_bytes(sig).unwrap();
        let res = sig.verify(true, &msg, &self.dst, &[], &self.pk, false);
        res == BLST_ERROR::BLST_SUCCESS
    }
    pub fn get_pubkey(&self) -> [u8; 48] {
        self.pk.compress()
    }
}
