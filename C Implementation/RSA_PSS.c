#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define N_ITERATIONS 5
#define M_OPERATIONS 500


void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main() {
    int key_sizes[] = { 1024, 2048, 4096 }; 
    int num_sizes = 3;

    const unsigned char message[] = "CA_Trabalho_2";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, message, sizeof(message) - 1);
    EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md_ctx);

    printf("--- RSA PSS Performance Evaluation ---\n");

    for (int i = 0; i < num_sizes; i++) {
        int bits = key_sizes[i];
        printf("\n[Testing RSA-PSS %d bits]\n", bits);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY* pkey = NULL;
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
        EVP_PKEY_keygen(ctx, &pkey);
        EVP_PKEY_CTX_free(ctx);

        unsigned char* signature = malloc(EVP_PKEY_size(pkey));
        size_t signature_len = EVP_PKEY_size(pkey);

        // --- SIGN (Mede tempo com entropia do Salt incluida) ---
        double min_time_sign = 1e9;
        
        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new(pkey, NULL);
                size_t temp_len = EVP_PKEY_size(pkey);

                if (EVP_PKEY_sign_init(sign_ctx) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(sign_ctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_pss_saltlen(sign_ctx, -1) <= 0 || 
                    EVP_PKEY_sign(sign_ctx, signature, &temp_len, digest, digest_len) <= 0) 
                {
                     handleErrors();
                }
                signature_len = temp_len; // Atualiza len real
                EVP_PKEY_CTX_free(sign_ctx);
            }
            clock_t end = clock();
            double avg_op = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg_op < min_time_sign) min_time_sign = avg_op;
        }

        // --- VERIFY---
        double min_time_verify = 1e9;

        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
                if (EVP_PKEY_verify_init(verify_ctx) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_pss_saltlen(verify_ctx, -1) <= 0 ||
                    EVP_PKEY_verify(verify_ctx, signature, signature_len, digest, digest_len) <= 0)
                {
                    printf("Falha PSS verify\n"); exit(1);
                }
                EVP_PKEY_CTX_free(verify_ctx);
            }
            clock_t end = clock();
            double avg_op = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg_op < min_time_verify) min_time_verify = avg_op;
        }

        printf("  -> Sign Time: %.4f ms\n", min_time_sign);
        printf("  -> Verify Time: %.4f ms\n", min_time_verify);

        free(signature);
        EVP_PKEY_free(pkey);
    }
    return 0;
}