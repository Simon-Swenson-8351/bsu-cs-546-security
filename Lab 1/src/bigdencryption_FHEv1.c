#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include "bigdencryption_common.h"
#include "bigdencryption_FHEv1.h"

FHEv1_Key *FHEv1_Key_createFromKeyLen(size_t keyLen) {
	FHEv1_Key *result = (FHEv1_Key *)calloc(sizeof(FHEv1_Key), 1);
	time_t curTime;

	BIGD one = bdNew();
	bdSetShort(one, 1);
	BIGD two = bdNew();
	bdSetShort(two, 2);
	BIGD temp = bdNew();
	BIGD temp2 = bdNew();

	BIGD q = bdNew();
	BIGD p_2 = bdNew();
	BIGD p_3 = bdNew();
	BIGD h_1 = bdNew();
	BIGD h_2 = bdNew();

	// Need to free all except (all above):
	// p1
	// n
	// g_1
	// g_2
	// t
	BIGD p_1 = bdNew();
	BIGD n = bdNew();
	BIGD g_1 = bdNew();
	BIGD g_2 = bdNew();
	BIGD t = bdNew();

	do {
		curTime = time(NULL);
		// Using curTime directly here is a bit hacky, but we can use sizeof
		// to ensure we don't run off the end of the field.
		bdGeneratePrime(p_1, keyLen, 3, (unsigned char *)(&curTime), sizeof(time_t), kernelRandCallback);
		// Find q = 2p_1 + 1.
		bdMultiply(temp, p_1, two);
		bdAdd(q, temp, one);
	} while(!bdIsPrime(q, 3));

	result->encryptionKey.p_1 = p_1;

	curTime = time(NULL);
	bdGeneratePrime(p_2, keyLen, 3, (unsigned char *)(&curTime), sizeof(time_t), kernelRandCallback);

	bdMultiply(n, p_1, p_2);

	result->encryptionKey.n = n;
	result->encryptionKey.n = n;

	curTime = time(NULL);
	bdGeneratePrime(p_3, keyLen, 3, (unsigned char *)(&curTime), sizeof(time_t), kernelRandCallback);

	bdMultiply(t, q, p_3);

	result->operationalKey.t = t;

	randInRange(h_1, t);
	bdSubtract(temp, p_3, one);
	bdMultiply(temp2, temp, two);
	bdModExp(g_1, h_1, temp2, t);

	randInRange(h_2, t);
	bdModExp(g_2, h_2, temp2, t);

	result->operationalKey.g_1 = g_1;
	result->operationalKey.g_2 = g_2;
	
	bdFree(&one);
	bdFree(&two);
	bdFree(&temp);
	bdFree(&temp2);
	bdFree(&h_1);
	bdFree(&h_2);
	bdFree(&q);
	bdFree(&p_2);
	bdFree(&p_3);

	return result;
}

FHEv1_Key *FHEv1_Key_createFromString(char *str) {
    FHEv1_Key *result = (FHEv1_Key *)calloc(sizeof(FHEv1_Key), 1);
    
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

	BIGD g_1 = bdNew();
	bdConvFromDecimal(g_1, str + starts[2]);
	result->operationalKey.g_1 = g_1;

	BIGD g_2 = bdNew();
	bdConvFromDecimal(g_2, str + starts[3]);
	result->operationalKey.g_2 = g_2;

	BIGD t = bdNew();
	bdConvFromDecimal(t, str + starts[4]);
	result->operationalKey.t = t;

	return result;
}

char *FHEv1_Key_toNewString(FHEv1_Key *key) {
	size_t sizes[5];
	sizes[0] = bdConvToDecimal(key->encryptionKey.p_1, NULL, 0);
	sizes[1] = bdConvToDecimal(key->encryptionKey.n, NULL, 0);
	sizes[2] = bdConvToDecimal(key->operationalKey.g_1, NULL, 0);
	sizes[3] = bdConvToDecimal(key->operationalKey.g_2, NULL, 0);
	sizes[4] = bdConvToDecimal(key->operationalKey.t, NULL, 0);
	// 1 for each newline, 1 for \0
	size_t totalSize = sizes[0] + sizes[1] + sizes[2] + sizes[3] + sizes[4] + 6;
	char *result = (char *)calloc(sizeof(char), totalSize);

	bdConvToDecimal(key->encryptionKey.p_1, result, sizes[0] + 1);
	result[sizes[0]] = '\n';

	bdConvToDecimal(key->encryptionKey.n, result + sizes[0] + 1, sizes[1] + 1);
	result[sizes[0] + sizes[1] + 1] = '\n';

	bdConvToDecimal(key->operationalKey.g_1, result + sizes[0] + sizes[1] + 2, sizes[2] + 1);
	result[sizes[0] + sizes[1] + sizes[2] + 2] = '\n';

	bdConvToDecimal(key->operationalKey.g_2, result + sizes[0] + sizes[1] + sizes[2] + 3, sizes[3] + 1);
	result[sizes[0] + sizes[1] + sizes[2] + sizes[3] + 3] = '\n';

	bdConvToDecimal(key->operationalKey.t, result + sizes[0] + sizes[1] + sizes[2] + sizes[3] + 4, sizes[4] + 1);
	result[sizes[0] + sizes[1] + sizes[2] + sizes[3] + sizes[4] + 4] = '\n';

	result[totalSize - 1] = '\0';

	return result;
}

void FHEv1_Key_destroy(FHEv1_Key *key) {
	bdFree(&(key->operationalKey.t));
	bdFree(&(key->operationalKey.g_2));
	bdFree(&(key->operationalKey.g_1));
	bdFree(&(key->encryptionKey.n));
	bdFree(&(key->encryptionKey.n));
	free(key);
}

void FHEv1_encrypt(BIGD ciphertext, BIGD plaintext, FHEv1_EncryptionKey *key) {
	BIGD zero = bdNew();
	bdSetZero(zero);
	if(bdCompare(plaintext, zero) < 0 || bdCompare(plaintext, key->p_1) >= 0) {
		fprintf(stderr, "Message must be a natural number >= 0 and < p_1\n");
		exit(1);
	}
	BIGD randnum = bdNew();
	randInRange(randnum, key->n);
	BIGD temp = bdNew();
	BIGD temp2 = bdNew();

	bdModMult(temp, randnum, key->p_1, key->n);
	bdAdd(temp2, temp, plaintext);
	bdModulo(ciphertext, temp2, key->n);

	bdFree(&temp2);
	bdFree(&temp);
	bdFree(&randnum);
	bdFree(&zero);
}

void FHEv1_decrypt(BIGD plaintext, BIGD ciphertext, FHEv1_EncryptionKey *key) {
	BIGD zero = bdNew();
	bdSetZero(zero);
	if(bdCompare(ciphertext, zero) < 0 || bdCompare(ciphertext, key->n) >= 0) {
		fprintf(stderr, "Ciphertext must be a natural number >= 0 and < N\n");
		exit(1);
	}

	bdModulo(plaintext, ciphertext, key->p_1);

	bdFree(&zero);
}

void FHEv1_homomorphicAdd(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key) {
	BIGD temp = bdNew();

	bdAdd(temp, ciphertext1, ciphertext2);
	bdModulo(ciphertextResult, temp, key->n);

	bdFree(&temp);
}

void FHEv1_homomorphicMultiply(BIGD ciphertextResult, BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key) {
	bdModMult(ciphertextResult, ciphertext1, ciphertext2, key->n);
}

bool FHEv1_homomorphicEquality(BIGD ciphertext1, BIGD ciphertext2, FHEv1_OperatonalKey *key) {
	bool result = true;
	BIGD zero = bdNew();
	bdSetZero(zero);
	BIGD one = bdNew();
	bdSetShort(one, 1);
	BIGD temp = bdNew();
	BIGD temp2 = bdNew();

	if(bdCompare(ciphertext1, ciphertext2) >= 0) {
		bdSubtract(temp, ciphertext1, ciphertext2);
	} else {
		bdSubtract(temp, ciphertext2, ciphertext1);
	}
	bdModExp(temp2, key->g_1, temp, key->t);
	if(bdCompare(temp2, one) != 0) {
		result = false;
	}

	bdModExp(temp2, key->g_2, temp, key->t);
	if(bdCompare(temp2, one) != 0) {
		result = false;
	}

	bdFree(&temp2);
	bdFree(&temp);
	bdFree(&one);
	bdFree(&zero);

	return result;
}