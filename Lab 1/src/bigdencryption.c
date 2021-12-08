#include <stdio.h>
#include <stdbool.h>
#include "bigdencryption.h"
#include "bigd.h"

typedef struct EncryptionKey_FHEv1 {
	BIGD p_1;
	BIGD n;
} EncryptionKey_FHEv1;

typedef struct OperatonalKey_FHEv1 {
	BIGD n;
	BIGD g_1;
	BIGD g_2;
	BIGD t;
} OperatonalKey_FHEv1;

typedef struct Key_FHEv1 {
    EncryptionKey_FHEv1 encryptionKey;
    OperatonalKey_FHEv1 operationalKey;
} Key_FHEv1;

typedef struct EncryptionKey_FHEv2 {
	BIGD p_1;
	BIGD n;
	BIGD wExp; // 2^w
} EncryptionKey_FHEv2;

typedef struct OperatonalKey_FHEv2 {
	BIGD n;
} OperatonalKey_FHEv2;

typedef struct KeyParams_FHEv2 {
	BIGD w;
	BIGD z;
} KeyParams_FHEv2;

typedef struct Key_FHEv2 {
    EncryptionKey_FHEv2 encryptionKey;
    OperatonalKey_FHEv2 operationalKey;
    KeyParams_FHEv2 keyParams;
} Key_FHEv2;

typedef struct BIGDEncryptor {
    void (*encrypt)(BIGD, BIGD);
    void (*decrypt)(BIGD, BIGD);
    void (*homomorphicAdd)(BIGD, BIGD, BIGD);
    void (*homomorphicMultiply)(BIGD, BIGD, BIGD);
} BIGDEncryptor;

typedef struct BIGDEncryptor_FHEv1 {
    BIGDEncryptor inherited;
    bool (*homomorphicEquality)(BIGD, BIGD);
	Key_FHEv1 *key;
} BIGDEncryptor_FHEv1;

typedef struct BIGDEncryptor_FHEv2 {
	BIGDEncryptor inherited;
	Key_FHEv2 *key;
} BIGDEncryptor_FHEv2;

Key_FHEv1 *Key_FHEv1_createFromParameters(size_t keysize);
Key_FHEv1 *Key_FHEv1_createFromString(char *keyString);
Key_FHEv1 *Key_FHEv1_createFromStrings(char *p_1Str, char *nStr, char *g_1Str, char *g_2Str, char *tStr);
void Key_FHEv1_destroy(Key_FHEv1 *key);

Key_FHEv2 *Key_FHEv2_createFromParameters(size_t keysize);
Key_FHEv2 *Key_FHEv2_createFromString(char *keyString);
Key_FHEv2 *Key_FHEv2_createFromStrings(char *p_1Str, char *wExpStr, char *nStr, char *wStr, char *zStr);
void Key_FHEv2_destroy(Key_FHEv2 *key);

BIGDEncryptor *BIGDEncryptor_FHEv1_create(Key_FHEv1 *key);
BIGDEncryptor *BIGDEncryptor_FHEv2_create(Key_FHEv2 *key);