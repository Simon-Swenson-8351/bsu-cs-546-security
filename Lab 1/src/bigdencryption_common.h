#ifndef BIGDENCRYPTION_COMMON_H__
#define BIGDENCRYPTION_COMMON_H__

#include <stddef.h>
#include "bigd.h"

void randInRange(BIGD result, BIGD max);
void printBIGD(BIGD toPrint);
int kernelRandCallback(unsigned char *bytes, size_t nbytes, const unsigned char *seed, size_t seedlen);

#endif // BIGDENCRYPTION_COMMON_H__