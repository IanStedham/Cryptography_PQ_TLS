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

int main(int argc, char *argv[]) { 

    //read alices dilithium PK
    size_t alice_pk_len;
    uint8_t *alice_pk = Read_Hex_File(argv[1], &alice_pk_len);

    //Read bobby's Kyber SK
    size_t bob_sk_len;
    uint8_t *bob_sk = Read_Hex_File(argv[2], &bob_sk_len);
    
    //Read dilithium signature
    size_t dil_sig_len;
    uint8_t *dilithium_signature = Read_Hex_File("dilithium_signature.txt", &dil_sig_len);

    //read Kyber Cipher [CT_A]
    size_t CT_A_len;
    uint8_t *CT_A = Read_Hex_File("kyber_ciphertext.txt", &CT_A_len);

    if (alice_pk_len != OQS_SIG_dilithium_2_length_public_key 
        || bob_sk_len != OQS_KEM_kyber_512_length_secret_key
        || dil_sig_len != OQS_SIG_dilithium_2_length_signature
        || CT_A_len != OQS_KEM_kyber_512_length_ciphertext
    ) {
        printf("Error: Size mismatch\n");
        exit(1);
    }

    //Using alice's pk, verify sig
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);    
    OQS_STATUS rc = OQS_SIG_verify(sig, CT_A, CT_A_len, dilithium_signature, dil_sig_len, alice_pk);

    if (rc != OQS_SUCCESS) {
        printf("Signature verification failed\n"); 
        exit(1);
    }

    //Decapsulate Kyber ciphertext using SK
    uint8_t K1_B[OQS_KEM_kyber_512_length_shared_secret]; //shared secret
    //OQS_KEM_kyber_512_decaps(K1_B, CT_A, bob_sk);

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (OQS_KEM_decaps(kem, K1_B, CT_A, bob_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: decapsulation failed\n");
        return 1;
    }
    Write_Hex_File("bob_shared_secret.txt", K1_B, OQS_KEM_kyber_512_length_shared_secret);

    OQS_SIG_free(sig);
    OQS_KEM_free(kem);

    return 0;
}
/*
// Constructs an OQS_KEM object for a particular algorithm
OQS_KEM *OQS_KEM_new(const char *method_name);

// OQS Keypair generation
OQS_STATUS OQS_KEM_keypair(const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key);

// Key encapsulation algorithm
OQS_STATUS OQS_KEM_encaps(const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key);

// Decapsulation algorithm
OQS_STATUS OQS_KEM_decaps(const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key);

// Frees an OQS_KEM object that was constructed by OQS_KEM_new
void OQS_KEM_free(OQS_KEM *kem);
*/


/*
// Constructs an OQS_SIG object for a particular algorithm
OQS_SIG *OQS_SIG_new(const char *method_name);

// Keypair generation
OQS_STATUS OQS_SIG_keypair(const OQS_SIG *sig, uint8_t *public_key, uint8_t *secret_key);

// Signature generation algorithm
OQS_STATUS OQS_SIG_sign(const OQS_SIG *sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t *secret_key);

// Signature verification algorithm
OQS_STATUS OQS_SIG_verify(const OQS_SIG *sig, const uint8_t *message, size_t message_len, const uint8_t *signature, size_t signature_len, const uint8_t *public_key);

// Frees an OQS_SIG object that was constructed by OQS_SIG_new
void OQS_SIG_free(OQS_SIG *sig);
*/

// Functions

// Read file content
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
