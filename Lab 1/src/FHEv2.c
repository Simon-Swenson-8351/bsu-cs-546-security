#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <linux/random.h>
#include "bigd.h"
#include "bigdencryption_FHEv2.h"
#include "bigdencryption_common.h"

#define PROG_NAME "FHEv1"
#define NUMMODES 6

typedef enum {
	M_K_KEYGEN,
	M_E_ENCRYPT,
	M_D_DECRYPT,
	M_B_ENCDEC,
	M_A_HOMOADD,
	M_M_HOMOMULT
} Mode;

const char modeChar[] = {'k', 'e', 'd', 'b', 'a', 'm'};
const char *modeForm[] = {
	"<key size> <w> <z> <KeyFileName>",
	"<m> <KeyFileName>",
	"<C_m> <KeyFileName>",
	"<m> <KeyFileName>",
	"<-e <m_1> | C_m_1> <-e <m_2> | C_m_2> <KeyFileName>",
	"<-e <m_1> | C_m_1> <-e <m_2> | C_m_2> <KeyFileName>"
};
const char *modeDescr[] = {
	"generate key", 
	"encrypt", 
	"decrypt", 
	"encrypt, then decrypt", 
	"homomorphic addition", 
	"homomorphic multiplication"
};
const int minArgs[] = {6, 4, 4, 4, 5, 5};
const int maxArgs[] = {6, 4, 4, 4, 7, 7};

void modeKeygen(int argc, char *argv[]);
void modeEncrypt(int argc, char *argv[]);
void modeDecrypt(int argc, char *argv[]);
void modeEncryptDecrypt(int argc, char *argv[]);
void modeHomomorphicAdd(int argc, char *argv[]);
void modeHomomorphicMultiply(int argc, char *argv[]);

// This is useful for all homomorphic operations because they use similar command line arguments.
// Basically handles <-e <m_1> | C_m_1>
int parseCiphertextOrConvertFromPlaintext(BIGD ciphertext, int argc, char *argv[], int pos, FHEv2_EncryptionKey *ek, FHEv2_KeyParams *kp);

void putKey(FHEv2_Key *key, char *filepath);
FHEv2_Key *getKey(char *filepath);

void printUsageAndExit(void);

int main(int argc, char *argv[]) {

	// Set a default mode to get rid of a warning.
	Mode m = M_K_KEYGEN;
	// Check that the number of arguments and usage mode argument make sense
	if(argc < 2 || strlen(argv[1]) != 2) {
		printUsageAndExit();
	}

	// Get the usage mode
	bool set = false;
	int i;
	for(i = 0; i < NUMMODES; i++) {
		if(argv[1][1] == modeChar[i]) {
			m = (Mode)i;
			set = true;
			break;
		}
	}
	if(!set) {
		printUsageAndExit();
	}

	// Do more specific checking to see if the number of arguments for the mode
	// makes sense.
	if(argc < minArgs[(int)m] || argc > maxArgs[(int)m]) {
		printUsageAndExit();
	}

	// Parse arguments and do the correct mode
	switch(m) {
		case M_K_KEYGEN:
			modeKeygen(argc, argv);
			break;
		case M_E_ENCRYPT:
			modeEncrypt(argc, argv);
			break;
		case M_D_DECRYPT:
			modeDecrypt(argc, argv);
			break;
		case M_B_ENCDEC:
			modeEncryptDecrypt(argc, argv);
			break;
		case M_A_HOMOADD:
			modeHomomorphicAdd(argc, argv);
			break;
		case M_M_HOMOMULT:
			modeHomomorphicMultiply(argc, argv);
			break;
		default:
			fprintf(stderr, "Unknown usage: %d", (int)m);
			exit(1);
	}
}

void modeKeygen(int argc, char *argv[]) {
	// Casting may truncate depending on size_t size. We rely on the user entering a
	// not so crazy big number here.
	size_t numDigits = (size_t)atoll(argv[2]);
	size_t w = (size_t)atoll(argv[3]);
	size_t z = (size_t)atoll(argv[4]);
	FHEv2_Key *key = FHEv2_Key_createFromParams(numDigits, w, z);
	putKey(key, argv[5]);
	FHEv2_Key_destroy(key);
}

void modeEncrypt(int argc, char *argv[]) {
	BIGD ciphertext = bdNew();
	BIGD plaintext = bdNew();
	size_t allocd = bdConvFromDecimal(plaintext, argv[2]);
	if(allocd == 0) {
		fprintf(stderr, "Could not convert from %s. Was it a natural number?\n", argv[2]);
		exit(1);
	}
	FHEv2_Key *key = getKey(argv[3]);

	FHEv2_encrypt(ciphertext, plaintext, &(key->encryptionKey), &(key->keyParams));

	printBIGD(ciphertext);
	printf("\n");

	FHEv2_Key_destroy(key);
	bdFree(&plaintext);
	bdFree(&ciphertext);
}

void modeDecrypt(int argc, char *argv[]) {
	BIGD ciphertext = bdNew();
	size_t allocd = bdConvFromDecimal(ciphertext, argv[2]);
	if(allocd == 0) {
		fprintf(stderr, "Could not convert from %s. Was it a natural number?\n", argv[2]);
		exit(1);
	}
	FHEv2_Key *key = getKey(argv[3]);
	BIGD plaintext = bdNew();

	FHEv2_decrypt(plaintext, ciphertext, &(key->encryptionKey));

	printBIGD(plaintext);
	printf("\n");

	bdFree(&plaintext);
	FHEv2_Key_destroy(key);
	bdFree(&ciphertext);
}

void modeEncryptDecrypt(int argc, char *argv[]) {
	BIGD plaintext = bdNew();
	size_t allocd = bdConvFromDecimal(plaintext, argv[2]);
	if(allocd == 0) {
		fprintf(stderr, "Could not convert from %s. Was it a natural number?\n", argv[2]);
		exit(1);
	}
	FHEv2_Key *key = getKey(argv[3]);
	BIGD ciphertext = bdNew();

	printf("%s\n", argv[2]);

	FHEv2_encrypt(ciphertext, plaintext, &(key->encryptionKey), &(key->keyParams));

	printBIGD(ciphertext);
	printf("\n");

	FHEv2_decrypt(plaintext, ciphertext, &(key->encryptionKey));

	printBIGD(plaintext);
	printf("\n");

	bdFree(&ciphertext);
	FHEv2_Key_destroy(key);
	bdFree(&plaintext);
}

void modeHomomorphicAdd(int argc, char *argv[]) {
	BIGD ct1 = bdNew();
	BIGD ct2 = bdNew();
	BIGD ctr = bdNew();
	FHEv2_Key *key = getKey(argv[argc - 1]);
	int pos = 2;
	pos = parseCiphertextOrConvertFromPlaintext(ct1, argc, argv, pos, &(key->encryptionKey), &(key->keyParams));
	parseCiphertextOrConvertFromPlaintext(ct2, argc, argv, pos, &(key->encryptionKey), &(key->keyParams));

	FHEv2_homomorphicAdd(ctr, ct1, ct2, &(key->operationalKey));

	printBIGD(ctr);
	printf("\n");

	FHEv2_Key_destroy(key);
	bdFree(&ctr);
	bdFree(&ct2);
	bdFree(&ct1);
}

void modeHomomorphicMultiply(int argc, char *argv[]) {
	BIGD ct1 = bdNew();
	BIGD ct2 = bdNew();
	BIGD ctr = bdNew();
	FHEv2_Key *key = getKey(argv[argc - 1]);
	int pos = 2;
	pos = parseCiphertextOrConvertFromPlaintext(ct1, argc, argv, pos, &(key->encryptionKey), &(key->keyParams));
	parseCiphertextOrConvertFromPlaintext(ct2, argc, argv, pos, &(key->encryptionKey), &(key->keyParams));

	FHEv2_homomorphicMultiply(ctr, ct1, ct2, &(key->operationalKey));

	printBIGD(ctr);
	printf("\n");
	
	FHEv2_Key_destroy(key);
	bdFree(&ctr);
	bdFree(&ct2);
	bdFree(&ct1);
}

int parseCiphertextOrConvertFromPlaintext(BIGD ciphertext, int argc, char *argv[], int pos, FHEv2_EncryptionKey *ek, FHEv2_KeyParams *kp) {
	int result;
	if(strlen(argv[pos]) == 2 && argv[pos][0] == '-' && argv[pos][1] == 'e') {
		BIGD plaintext = bdNew();
		size_t allocd = bdConvFromDecimal(plaintext, argv[pos + 1]);
		if(allocd == 0) {
			fprintf(stderr, "Could not convert from %s. Was it a natural number?\n", argv[2]);
			exit(1);
		}
		FHEv2_encrypt(ciphertext, plaintext, ek, kp);
		bdFree(&plaintext);
		result = pos + 2;
	} else {
		size_t allocd = bdConvFromDecimal(ciphertext, argv[pos]);
		if(allocd == 0) {
			fprintf(stderr, "Could not convert from %s. Was it a natural number?\n", argv[2]);
			exit(1);
		}
		result = pos + 1;
	}
	return result;
}

void putKey(FHEv2_Key *key, char *filepath) {
	FILE *keyfile = fopen(filepath, "w");
	if(!keyfile) {
		fprintf(stderr, "Could not open file %s for writing\n", filepath);
		exit(1);
	}

	char *buf = FHEv2_Key_toNewString(key);
	fwrite(buf, strlen(buf), 1, keyfile);

	free(buf);
	fclose(keyfile);
}

FHEv2_Key *getKey(char *filepath) {
	FILE *keyfile = fopen(filepath, "r");
	if(!keyfile) {
		fprintf(stderr, "Could not open file %s for reading\n", filepath);
		exit(1);
	}

	fseek(keyfile, 0L, SEEK_END);
	size_t bufSize = (size_t)(ftell(keyfile) + 1);
	fseek(keyfile, 0L, SEEK_SET);

	char *buf = (char *)calloc(sizeof(char), bufSize);
	fread(buf, bufSize, 1, keyfile);
	buf[bufSize - 1] = '\0';

	FHEv2_Key *result = FHEv2_Key_createFromString(buf);

	return result;
}

void printUsageAndExit() {
	int i;
	printf("Usage mode needed: \n");
	for(i = 0; i < NUMMODES; i++) {
		printf("%s -%c %s: %s\n", PROG_NAME, modeChar[i], modeForm[i], modeDescr[i]);
	}
	exit(1);
}