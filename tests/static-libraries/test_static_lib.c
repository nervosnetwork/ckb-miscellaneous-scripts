
// declarations
#include "rsa_secp256k1.h"
// must include these header files again, because we also need the definitions
#include "string.h"
#include "blockchain.h"
#include "blake2b.h"
#include "ckb_syscalls.h"

int main() {
  // just compile, don't run
  load_prefilled_data(0, 0);
  validate_signature_rsa(0, 0, 0, 0, 0, 0, 0);
  validate_signature_secp256k1(0, 0, 0, 0, 0, 0, 0);
  return 0;
}
