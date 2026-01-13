#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h> // Necessario para os NIDs
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#define N_ITERATIONS 5
#define M_OPERATIONS 500


// Em vez de strings, usamos os IDs inteiros (NIDs) que nao falham
int curves_P[] = { NID_X9_62_prime192v1, NID_X9_62_prime256v1, NID_secp521r1 };
int curves_K[] = { NID_sect163k1, NID_sect233k1, NID_sect409k1 };
int curves_B[] = { NID_sect163r2, NID_sect283r1, NID_sect571r1 };

// Nomes apenas para printar no ecra
const char* names_P[] = { "NIST P-192", "NIST P-256", "NIST P-521" };
const char* names_K[] = { "K-163", "K-233", "K-409" };
const char* names_B[] = { "B-163", "B-283", "B-571" };

void run_test_group(const char* group_name, int curves[], const char* names[], int num_curves, 
                    const unsigned char* digest, int digest_len) {
    
    printf("\n=== Testing Group: %s ===\n", group_name);

    for (int i = 0; i < num_curves; i++) {
        int curve_nid = curves[i];
        printf("Curve: %s ... ", names[i]);

        // 1. Keygen usando NID (Mais seguro que string)
        EVP_PKEY_CTX* kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY* pkey = NULL;

        if (EVP_PKEY_keygen_init(kctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, curve_nid) <= 0 ||
            EVP_PKEY_keygen(kctx, &pkey) <= 0) {
            printf("Erro: Curva nao suportada ou erro keygen.\n");
            EVP_PKEY_CTX_free(kctx);
            continue;
        }
        EVP_PKEY_CTX_free(kctx);

        // Buffer
        size_t sig_len = EVP_PKEY_size(pkey);
        unsigned char* signature = malloc(sig_len);

        // 2. Sign Measurement 
        double min_sign = 1e9;
        size_t written_len = 0;

        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* sctx = EVP_PKEY_CTX_new(pkey, NULL);
                size_t tlen = sig_len;
                if (EVP_PKEY_sign_init(sctx) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(sctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_sign(sctx, signature, &tlen, digest, digest_len) <= 0) {
                    // Erro silencioso no loop para nao spammar
                }
                written_len = tlen;
                EVP_PKEY_CTX_free(sctx);
            }
            clock_t end = clock();
            double avg = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg < min_sign) min_sign = avg;
        }

        // 3. Verify Measurement 
        double min_verify = 1e9;
        
        for (int n = 0; n < N_ITERATIONS; n++) {
            clock_t start = clock();
            for (int m = 0; m < M_OPERATIONS; m++) {
                EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pkey, NULL);
                if (EVP_PKEY_verify_init(vctx) <= 0 ||
                    EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0 ||
                    EVP_PKEY_verify(vctx, signature, written_len, digest, digest_len) <= 0) {
                    // Erro
                }
                EVP_PKEY_CTX_free(vctx);
            }
            clock_t end = clock();
            double avg = (((double)(end - start)) * 1000.0 / CLOCKS_PER_SEC) / M_OPERATIONS;
            if (avg < min_verify) min_verify = avg;
        }

        printf("Sign: %.4f ms | Verify: %.4f ms\n", min_sign, min_verify);

        free(signature);
        EVP_PKEY_free(pkey);
    }
}

int main() {
    const unsigned char message[] = "CA_Trabalho_2";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned int digest_len = SHA256_DIGEST_LENGTH;

    SHA256(message, sizeof(message) - 1, digest); 

    printf("--- ECDSA Performance Evaluation (3 Types x 3 Sizes) ---\n");
    
    run_test_group("NIST P-Curves (Prime)", curves_P, names_P, 3, digest, digest_len);
    run_test_group("NIST K-Curves (Koblitz)", curves_K, names_K, 3, digest, digest_len);
    run_test_group("NIST B-Curves (Binary)", curves_B, names_B, 3, digest, digest_len);

    return 0;
}