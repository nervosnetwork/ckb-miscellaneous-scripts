#ifndef _SECP256K1_ECMULT_STATIC_CONTEXT_
#define _SECP256K1_ECMULT_STATIC_CONTEXT_
#include "src/group.h"
#define SC SECP256K1_GE_STORAGE_CONST
static const secp256k1_ge_storage secp256k1_ecmult_static_context[1][1] = {};
#undef SC
#endif
