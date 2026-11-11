#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h> 
#include <stdbool.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

char* Read_File(const char *filename, long *fileLen);
int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len);
uint8_t* Read_Hex_File(const char *filename, size_t *data_len);
void Write_File(const char *filename, const char *content);
void Convert_to_Hex(char *output, const uint8_t *input, size_t len);
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len);
void XOR_Bytes(uint8_t *output, const uint8_t *b1, const uint8_t *b2, size_t len);
int Compute_SHA256(const uint8_t *data, size_t data_len, uint8_t *hash_output);

#define OQS_KEM_kyber_512_length_public_key 800
#define OQS_KEM_kyber_512_length_secret_key 1632
#define OQS_KEM_kyber_512_length_ciphertext 768
#define OQS_KEM_kyber_512_length_shared_secret 32
#define OQS_KEM_kyber_512_length_keypair_seed 0

#define OQS_SIG_dilithium_2_length_public_key 1312
#define OQS_SIG_dilithium_2_length_secret_key 2528
#define OQS_SIG_dilithium_2_length_signature 2420

int main(int argc, char *argv[]) { 
    size_t bob_kyber_public_key_length;
    unsigned char *bob_kyber_public_key = Read_Hex_File(argv[1], &bob_kyber_public_key_length);

    size_t alice_dilithium_private_key_length;
    unsigned char *alice_dilithium_private_key = Read_Hex_File(argv[2], &alice_dilithium_private_key_length);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);

    uint8_t *ciphertext = malloc(OQS_KEM_kyber_512_length_ciphertext);
    uint8_t *K1A = malloc(OQS_KEM_kyber_512_length_shared_secret);
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    OQS_STATUS rc = OQS_KEM_encaps(kem, ciphertext, K1A, bob_kyber_public_key);
    if (rc != OQS_SUCCESS) {
        printf("error on key encapsulation\n");
    }

    uint8_t *signature = malloc(OQS_SIG_dilithium_2_length_signature);
    size_t signature_length;
    rc = OQS_SIG_sign(sig, signature, &signature_length, ciphertext, 
        (size_t)OQS_KEM_kyber_512_length_ciphertext, alice_dilithium_private_key);
    if (rc != OQS_SUCCESS) {
        printf("error on signature\n");
    }

    Write_Hex_File("kyber_ciphertext.txt", ciphertext, OQS_KEM_kyber_512_length_ciphertext);
    Write_Hex_File("dilithium_signature.txt", signature, signature_length);
    Write_Hex_File("alice_shared_secret.txt", K1A, OQS_KEM_kyber_512_length_shared_secret);
}

char* Read_File(const char *filename, long *fileLen) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *content = malloc(*fileLen + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    fread(content, 1, *fileLen, file);
    content[*fileLen] = '\0';
    fclose(file);
    return content;
}

// Convert hex string to bytes
int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len) {
    size_t hex_len = strlen(hex_input);
    int bytes = 0;
    for (size_t i = 0; i < hex_len; i += 2) {
        if (!isxdigit(hex_input[i]) || !isxdigit(hex_input[i+1])) {
            continue; 
        }
        if (bytes >= max_len) break; 
        sscanf(&hex_input[i], "%2hhx", &output[bytes]);
        bytes++;
    }
    return bytes;
}

// Read hex file 
uint8_t* Read_Hex_File(const char *filename, size_t *data_len) {
    long file_len;
    char *content = Read_File(filename, &file_len);
    if (!content) {
        *data_len = 0;
        return NULL;
    }
    uint8_t *data = malloc(file_len / 2 + 1);
    if (!data) {
        free(content);
        *data_len = 0;
        return NULL;
    }
    *data_len = Convert_from_Hex(data, content, file_len / 2 + 1);
    free(content);
    if (*data_len == 0) {
        free(data);
        return NULL;
    }
    return data;
}

// Write to file
void Write_File(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot write to %s\n", filename);
        return;
    }
    fputs(content, file);
    fclose(file);
}

// Convert bytes to hex string
void Convert_to_Hex(char *output, const uint8_t *input, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02X", input[i]);
    }
    output[len * 2] = '\0';
}

// Write hex file
void Write_Hex_File(const char *filename, const uint8_t *data, size_t len) {
    char *hex_str = malloc(len * 2 + 1);
    if (!hex_str) return;
    Convert_to_Hex(hex_str, data, len);
    Write_File(filename, hex_str);
    free(hex_str);
}

// assumes output has enough space (len) and b1, b2 are of the same length.
void XOR_Bytes(uint8_t *output, const uint8_t *b1, const uint8_t *b2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = b1[i] ^ b2[i];
    }
}

// compute SHA256 hash
// output buffer `hash_output` must be at least SHA256_DIGEST_LENGTH bytes.
int Compute_SHA256(const uint8_t *data, size_t data_len, uint8_t *hash_output) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int hash_len;

    md = EVP_sha256();
    if (md == NULL) {
        fprintf(stderr, "ERROR: EVP_sha256 failed.\n");
        return 0;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "ERROR: EVP_MD_CTX_new failed.\n");
        return 0;
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "ERROR: EVP_DigestInit_ex failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "ERROR: EVP_DigestUpdate failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash_output, &hash_len)) {
        fprintf(stderr, "ERROR: EVP_DigestFinal_ex failed.\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }

    EVP_MD_CTX_free(mdctx);

    if (hash_len != SHA256_DIGEST_LENGTH) {
        fprintf(stderr, "ERROR: SHA256 output length mismatch (got %u, expected %d).\n", hash_len, SHA256_DIGEST_LENGTH);
        return 0;
    }
    return 1;
}
    