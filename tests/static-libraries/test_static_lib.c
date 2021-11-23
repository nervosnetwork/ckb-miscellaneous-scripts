#include "rsa_secp256k1.h"

int main() {
  // just compile, don't run
  load_prefilled_data(0, 0);
  validate_signature_rsa(0, 0, 0, 0, 0, 0, 0);
  validate_signature_secp256k1(0, 0, 0, 0, 0, 0, 0);
  validate_secp256k1_blake2b_sighash_all(0);
  ckb_smt_verify(0, 0,  0, 0,  0, 0);

  return 0;
}
