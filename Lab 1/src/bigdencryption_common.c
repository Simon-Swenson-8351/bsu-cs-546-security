#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "bigdencryption_common.h"

void randInRange(BIGD result, BIGD max) {

	BIGD zero = bdNew();
	bdSetZero(zero);

	do {
		time_t t = time(NULL);
		bdRandomSeeded(result, bdBitLength(max), (unsigned char *)(&t), sizeof(time_t), kernelRandCallback);
	} while(bdCompare(result, zero) <= 0 || bdCompare(result, max) >= 0);

	bdFree(&zero);
}

void printBIGD(BIGD toPrint) {
	size_t reqSize = bdConvToDecimal(toPrint, NULL, 0);
	char *buf = (char *)calloc(reqSize + 1, 1);
	bdConvToDecimal(toPrint, buf, reqSize + 1);
	printf("%s", buf);
	free(buf);
}

// Calls the kernel's random number generator (/dev/urandom) to generate random numbers
// Since urandom uses device entropy to seed, the given seed and seedlen will be ignored.
// Note this is NOT cross-platform.
int kernelRandCallback(unsigned char *bytes, size_t nbytes, const unsigned char *seed, size_t seedlen) {
	FILE *ur = fopen("/dev/urandom", "r");
	if(!ur) {
		fprintf(stderr, "urandom could not be opened\n");
		exit(1);
	}

	fread((void *)bytes, nbytes, sizeof(unsigned char), ur);

	return 0;
}