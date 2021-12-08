#include <stddef.h>

#ifndef BIGDENCRYPTION_H__
#define BIGDENCRYPTION_H__

typedef struct {

} BIGDEncryptionKey;

typedef struct {

} BIGDOperationalKey;

typedef struct {

} BIGDKey;

typedef struct BIGDKey_FHEv1 BIGDKey_FHEv1;
typedef struct BIGDEncryptor BIGDEncryptor;


BIGDEncryptor *BIGDEncryption_newFHEv1Encryptor(BIGDKey_FHEv1 *key);

#endif // BIGDENCRYPTION_H__