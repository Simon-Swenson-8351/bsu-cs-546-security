#ifndef BIGDENCRYPTION_FHEV2_H__
#define BIGDENCRYPTION_FHEV2_H__

#include "bigd.h"

typedef struct FHEv2_EncryptionKey {
    BIGD p_1;
    BIGD n;
    BIGD wExp;
} FHEv2_EncryptionKey;

typedef struct FHEv2_OperatonalKey {
    BIGD n;
} FHEv2_OperatonalKey;

typedef struct FHEv2_KeyParams {
    size_t w;
    size_t z;
} FHEv2_KeyParams;

typedef struct FHEv2_Key {
    FHEv2_EncryptionKey encryptionKey;
    FHEv2_OperatonalKey operationalKey;
    FHEv2_KeyParams keyParams;
} FHEv2_Key;

FHEv2_Key *FHEv2_Key_createFromParams(size_t keyLen, size_t w, size_t z);
FHEv2_Key *FHEv2_Key_createFromString(char *str);
char *FHEv2_Key_toNewString(FHEv2_Key *key);
void FHEv2_Key_destroy(FHEv2_Key *key);

void FHEv2_encrypt(BIGD ciphertext, BIGD plaintext, FHEv2_EncryptionKey *encryptionKey, FHEv2_KeyParams *keyParams);
void FHEv2_decrypt(BIGD plaintext, BIGD ciphertext, FHEv2_EncryptionKey *key);
void FHEv2_homomorphicAdd(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv2_OperatonalKey *key);
void FHEv2_homomorphicMultiply(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv2_OperatonalKey *key);

#endif // BIGDENCRYPTION_FHEV2_H__