#ifndef _SECP256K1_ECMULT_STATIC_PRE_CONTEXT_
#define _SECP256K1_ECMULT_STATIC_PRE_CONTEXT_
#include "src/group.h"
#define SC SECP256K1_GE_STORAGE_CONST
static const secp256k1_ge_storage secp256k1_ecmult_static_pre_context[1] = {};
#ifdef USE_ENDOMORPHISM
static const secp256k1_ge_storage secp256k1_ecmult_static_pre128_context[1] = {
};
#endif
#undef SC
#endif
