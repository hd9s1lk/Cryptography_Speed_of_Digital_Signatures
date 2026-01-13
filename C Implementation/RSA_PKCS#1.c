#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

// Settings for measurement loop
#define N_ITERATIONS 5    
#define M_OPERATIONS 500   


void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int main()
{
    int key_sizes[] = { 1024, 2048, 4096 };
    int num_sizes = 3;

    // Mensagem e Digest (Calculado apenas uma vez fora do loop)
    const unsigned char message[] = "CA_Trabalho_2";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = 0;
    
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(md_ctx, message, sizeof(message) - 1);
    EVP_DigestFinal_ex(md_ctx, digest, &digest_len);
    EVP_MD_CTX_free(md_ctx);

    printf("--- RSA PKCS#1 Performance Evaluation ---\n");
    printf("N=%d iterations, M=%d operations per iteration\n\n", N_ITERATIONS, M_OPERATIONS);

    for (int i = 0; i < num_sizes; i++) {
        int bits = key_sizes[i];
        printf("\n[Testing RSA %d bits]\n", bits);

        // 1. Geração de Chaves
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        EVP_PKEY* pkey = NULL;
        if (EVP_PKEY_keygen_init(ctx) <= 0 ||
            EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0 ||
            EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            handleErrors();
        }
        EVP_PKEY_CTX_free(ctx);

        // Buffer de assinatura
        size_t max_sig_len = EVP_PKEY_size(pkey);
        unsigned char* signature = malloc(max_sig_len);
        size_t signature_len = 0;

        // --- MEDIÇÃO: ASSINATURA (Loop N e M) ---
        double min_time_sign = 1e9; 

        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new(pkey, NULL);
                size_t temp_len = max_sig_len;
                
                if (EVP_PKEY_sign_init(sign_ctx) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_padding(sign_ctx, RSA_PKCS1_PADDING) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(sign_ctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_sign(sign_ctx, signature, &temp_len, digest, digest_len) <= 0) {
                    handleErrors();
                }
                signature_len = temp_len; // Guarda o tamanho real
                EVP_PKEY_CTX_free(sign_ctx);
            }
            clock_t end = clock();
            double avg_op = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg_op < min_time_sign) min_time_sign = avg_op;
        }

        // --- MEDIÇÃO: VALIDAÇÃO (Loop N e M) - ATUALIZADO PARA EVP API ---
        double min_time_verify = 1e9;

        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* verify_ctx = EVP_PKEY_CTX_new(pkey, NULL);
                
                // Agora usamos a API moderna (EVP_PKEY_verify) em vez de RSA_verify
                if (EVP_PKEY_verify_init(verify_ctx) <= 0 ||
                    EVP_PKEY_CTX_set_rsa_padding(verify_ctx, RSA_PKCS1_PADDING) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(verify_ctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_verify(verify_ctx, signature, signature_len, digest, digest_len) <= 0) {
                    printf("Falha na verificacao!\n"); 
                    handleErrors();
                }
                EVP_PKEY_CTX_free(verify_ctx);
            }
            clock_t end = clock();
            double avg_op = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg_op < min_time_verify) min_time_verify = avg_op;
        }

        printf("  -> Sign Time (min avg): %.4f ms\n", min_time_sign);
        printf("  -> Verify Time (min avg): %.4f ms\n", min_time_verify);

        // Cleanup
        free(signature);
        EVP_PKEY_free(pkey);
    }

    return 0;
}