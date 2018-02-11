#include <stdio.h>
#include <string.h>
#include "AesCBC.h"

int GetAlignLen(int originLen) {
    return AES_BLOCK_SIZE - originLen % AES_BLOCK_SIZE + originLen;
}

bool AesCbcEncrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *crypted,
                   int &crypted_len) {
    if (data == NULL || key == NULL || crypted == NULL) {
        return false;
    }
    int pad_len = AES_BLOCK_SIZE - data_len % AES_BLOCK_SIZE;
    unsigned char *padding_data = new unsigned char[data_len + pad_len];
    memcpy(padding_data, data, data_len);

    for (int i = data_len; i < data_len + pad_len; i++) {
        padding_data[i] = (unsigned char) pad_len;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] = key[i];
    }
    AES_KEY aes;
    if (AES_set_encrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return false;
    }
    crypted_len = data_len + pad_len;
    AES_cbc_encrypt(padding_data, crypted, data_len + pad_len, &aes, iv, AES_ENCRYPT);

    delete padding_data;

    return true;
}

bool AesCbcDecrypt(unsigned char *data, int data_len, unsigned char *key, unsigned char *origin_data,
              int &origin_len) {
    if (data == NULL || key == NULL || origin_data == NULL) {
        return false;
    }
    unsigned char iv[AES_BLOCK_SIZE];
    for (int i = 0; i < AES_BLOCK_SIZE; i++) {
        iv[i] = key[i];
    }
    AES_KEY aes;
    if (AES_set_decrypt_key((unsigned char *) key, 128, &aes) < 0) {
        return false;
    }
    unsigned char *padding_data = new unsigned char[data_len];
    AES_cbc_encrypt(data, padding_data, data_len, &aes, iv, AES_DECRYPT);

    unsigned char pad_len = padding_data[data_len - 1];

    for (int i = 0; i < data_len - pad_len; i++) {
        origin_data[i] = padding_data[i];
    }
    origin_len = data_len - pad_len;
    return true;
}

int main() {
    char data[] = "random1234timestamp1514191551333";


    char key[] = "1234567812345678";
    int crypted_len = 0;
    unsigned char crypted[100];
    memset(crypted, 0, sizeof(crypted));
    AesCbcEncrypt((unsigned char *) data, strlen(data), (unsigned char *) key,
                  (unsigned char *) crypted, crypted_len);

    char origin[100];
    int origin_len = 0;
    AesCbcDecrypt(crypted, crypted_len, (unsigned char *) key, (unsigned char *) origin,
                  origin_len);
    printf("%s\n", origin);


    return 0;
}
