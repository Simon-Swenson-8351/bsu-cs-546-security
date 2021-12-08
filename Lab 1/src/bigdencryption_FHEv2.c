#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "bigdencryption_common.h"
#include "bigdencryption_FHEv2.h"

#define NUM_CONSECUTIVE_MULTS 5

// Function prototypes
void mPrime(BIGD mprime, BIGD plaintext, BIGD wExp, size_t z);

// Function implementations
FHEv2_Key *FHEv2_Key_createFromParams(size_t keyLen, size_t w, size_t z) {
    FHEv2_Key *result = (FHEv2_Key *)calloc(sizeof(FHEv2_Key), 1);

	time_t curTime;

	BIGD one = bdNew();
	bdSetShort(one, 1);

	BIGD p_2 = bdNew();

	// Need to free all except (all above):
	// p1
	// n
	// wExp
	BIGD p_1 = bdNew();
	BIGD n = bdNew();
    BIGD wExp = bdNew();


    if(keyLen < (NUM_CONSECUTIVE_MULTS + 1) * (w + z)) {
        fprintf(
            stderr,
            "Combination of w (%llu), z (%llu) and key length (%llu) was not large enough to ensure %d consecutive multiplications\n",
            (unsigned long long)w, (unsigned long long)z, (unsigned long long)keyLen, NUM_CONSECUTIVE_MULTS);
        exit(1);
    }

    result->keyParams.w = w;
    result->keyParams.z = z;
    bdShiftLeft(wExp, one, w);
    result->encryptionKey.wExp = wExp;

	curTime = time(NULL);
	// Using curTime directly here is a bit hacky, but we can use sizeof
	// to ensure we don't run off the end of the field.
	bdGeneratePrime(p_1, keyLen, 3, (unsigned char *)(&curTime), sizeof(time_t), kernelRandCallback);

	result->encryptionKey.p_1 = p_1;

	curTime = time(NULL);
	bdGeneratePrime(p_2, keyLen, 3, (unsigned char *)(&curTime), sizeof(time_t), kernelRandCallback);

	bdMultiply(n, p_1, p_2);

	result->encryptionKey.n = n;
	result->encryptionKey.n = n;
	
	bdFree(&p_2);
	bdFree(&one);

	return result;
}

FHEv2_Key *FHEv2_Key_createFromString(char *str) {
    FHEv2_Key *result = (FHEv2_Key *)calloc(sizeof(FHEv2_Key), 1);
    
    size_t starts[5];
    starts[0] = 0;
    int curStarts = 1;
    int i;
    for(i = 0; str[i] != '\0'; i++) {
        if(str[i] == '\n') {
            str[i] = '\0';
			starts[curStarts] = i + 1;
			curStarts++;
			if(curStarts >= 5) {
				break;
			}
        }
    }
	BIGD p_1 = bdNew();
	bdConvFromDecimal(p_1, str + starts[0]);
	result->encryptionKey.p_1 = p_1;

	BIGD n = bdNew();
	bdConvFromDecimal(n, str + starts[1]);
	result->encryptionKey.n = n;
	result->operationalKey.n = n;

	BIGD wExp = bdNew();
	bdConvFromDecimal(wExp, str + starts[2]);
	result->encryptionKey.wExp = wExp;

	result->keyParams.w = (size_t)atoll(str + starts[3]);
	result->keyParams.z = (size_t)atoll(str + starts[4]);

	return result;
}

char *FHEv2_Key_toNewString(FHEv2_Key *key) {
	size_t sizes[5];
	sizes[0] = bdConvToDecimal(key->encryptionKey.p_1, NULL, 0);
	sizes[1] = bdConvToDecimal(key->encryptionKey.n, NULL, 0);
	sizes[2] = bdConvToDecimal(key->encryptionKey.wExp, NULL, 0);
	char w[128];
    sprintf(w, "%llu", (unsigned long long)key->keyParams.w);
    sizes[3] = strlen(w);
    char z[128];
    sprintf(z, "%llu", (unsigned long long)key->keyParams.z);
    sizes[4] = strlen(z);

	// 1 for each newline, 1 for \0
	size_t totalSize = sizes[0] + sizes[1] + sizes[2] + sizes[3] + sizes[4] + 6;
	char *result = (char *)calloc(sizeof(char), totalSize);

	bdConvToDecimal(
        key->encryptionKey.p_1,
        result,
        sizes[0] + 1);
	result[sizes[0]] = '\n';

	bdConvToDecimal(
        key->encryptionKey.n,
        result + sizes[0] + 1,
        sizes[1] + 1);
	result[sizes[0] + sizes[1] + 1] = '\n';

	bdConvToDecimal(
        key->encryptionKey.wExp,
        result + sizes[0] + sizes[1] + 2,
        sizes[2] + 1);
	result[sizes[0] + sizes[1] + sizes[2] + 2] = '\n';

	sprintf(
        result + sizes[0] + sizes[1] + sizes[2] + 3,
        "%llu",
        (unsigned long long)key->keyParams.w);
	result[sizes[0] + sizes[1] + sizes[2] + sizes[3] + 3] = '\n';

	sprintf(
        result + sizes[0] + sizes[1] + sizes[2] + sizes[3] + 4,
        "%llu",
        (unsigned long long)key->keyParams.z);
	result[sizes[0] + sizes[1] + sizes[2] + sizes[3] + sizes[4] + 4] = '\n';

	result[totalSize - 1] = '\0';

	return result;
}

void FHEv2_Key_destroy(FHEv2_Key *key) {
    bdFree(&(key->encryptionKey.p_1));
    bdFree(&(key->encryptionKey.n));
    bdFree(&(key->encryptionKey.wExp));
    free(key);
}

void FHEv2_encrypt(BIGD ciphertext, BIGD plaintext, FHEv2_EncryptionKey *encryptionKey, FHEv2_KeyParams *keyParams) {
    BIGD zero = bdNew();
	bdSetZero(zero);
	if(bdCompare(plaintext, zero) < 0 || bdCompare(plaintext, encryptionKey->wExp) >= 0) {
		fprintf(stderr, "Message must be a natural number >= 0 and < 2^w\n");
		exit(1);
	}

    BIGD mprime = bdNew();
    mPrime(mprime, plaintext, encryptionKey->wExp, keyParams->z);
    BIGD randnum = bdNew();
	randInRange(randnum, encryptionKey->n);
    BIGD temp = bdNew();
    bdModMult(temp, randnum, encryptionKey->p_1, encryptionKey->n);
    BIGD temp2 = bdNew();
    bdAdd(temp2, temp, mprime);
    bdModulo(ciphertext, temp2, encryptionKey->n);

    bdFree(&temp2);
    bdFree(&temp);
    bdFree(&randnum);
    bdFree(&mprime);
    bdFree(&zero);
}

void FHEv2_decrypt(BIGD plaintext, BIGD ciphertext, FHEv2_EncryptionKey *key) {
    BIGD temp = bdNew();
    bdModulo(temp, ciphertext, key->p_1);
    bdModulo(plaintext, temp, key->wExp);
    bdFree(&temp);
}

void FHEv2_homomorphicAdd(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv2_OperatonalKey *key) {
	BIGD temp = bdNew();

	bdAdd(temp, ciphertext1, ciphertext2);
	bdModulo(ciphertextResult, temp, key->n);

	bdFree(&temp);
}

void FHEv2_homomorphicMultiply(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv2_OperatonalKey *key) {
	bdModMult(ciphertextResult, ciphertext1, ciphertext2, key->n);
}

void mPrime(BIGD mprime, BIGD plaintext, BIGD wExp, size_t z) {
    BIGD randomPadding = bdNew();
    time_t t = time(NULL);
    bdRandomSeeded(randomPadding, z, (unsigned char *)(&t), sizeof(time_t), kernelRandCallback);
    BIGD temp = bdNew();
    bdMultiply(temp, randomPadding, wExp);
    bdAdd(mprime, temp, plaintext);

    bdFree(&randomPadding);
    bdFree(&temp);
}