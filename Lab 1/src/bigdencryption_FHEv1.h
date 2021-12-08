#ifndef BIGDENCRYPTION_FHEV1_H__
#define BIGDENCRYPTION_FHEV1_H__

#include "bigd.h"

typedef struct FHEv1_EncryptionKey {
	BIGD p_1;
	BIGD n;
} FHEv1_EncryptionKey;

typedef struct FHEv1_OperatonalKey {
	BIGD n;
	BIGD g_1;
	BIGD g_2;
	BIGD t;
} FHEv1_OperatonalKey;

typedef struct FHEv1_Key {
    FHEv1_EncryptionKey encryptionKey;
    FHEv1_OperatonalKey operationalKey;
} FHEv1_Key;

FHEv1_Key *FHEv1_Key_createFromKeyLen(size_t keyLen);
FHEv1_Key *FHEv1_Key_createFromString(char *str);
char *FHEv1_Key_toNewString(FHEv1_Key *key);
void FHEv1_Key_destroy(FHEv1_Key *key);

void FHEv1_encrypt(BIGD ciphertext, BIGD plaintext, FHEv1_EncryptionKey *key);
void FHEv1_decrypt(BIGD plaintext, BIGD ciphertext, FHEv1_EncryptionKey *key);
void FHEv1_homomorphicAdd(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key);
void FHEv1_homomorphicMultiply(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key);
bool FHEv1_homomorphicEquality(BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key);

#endif // BIGDENCRYPTION_FHEV1_H__