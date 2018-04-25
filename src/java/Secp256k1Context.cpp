#include <stdlib.h>
#include <stdint.h>
#include "Secp256k1Context.h"
#include "include/secp256k1.h"

JNIEXPORT jlong
JNICALL Java_network_minter_mintercore_crypto_Secp256k1Context_secp256k1_1init_1context(JNIEnv *env,
                                                                                        jclass classObject) {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    (void) classObject;
    (void) env;

    return (uintptr_t) ctx;
}
