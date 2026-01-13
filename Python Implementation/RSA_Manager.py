import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

N_ITERATIONS = 5   
M_OPERATIONS = 100

KEY_SIZES = [1024, 2048, 4096] 
MESSAGE = b"CA_Trabalho_2"

def run_performance_test():
    print(f"--- RSA Performance Test (Library: cryptography) ---")
    print(f"N={N_ITERATIONS}, M={M_OPERATIONS}\n")

    for bits in KEY_SIZES:
        print(f"Generating {bits}-bit key...", end="", flush=True)
        # Geração de chave (não conta para o tempo de assinatura)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        public_key = private_key.public_key()
        print(" Done.")

        # --- . RSA PKCS#1 v1.5 ---
        print(f"Testing RSA-{bits} PKCS#1 v1.5:")
        
        # Medir Assinatura
        min_sign_time = float('inf')
        for _ in range(N_ITERATIONS):
            start = time.perf_counter()
            for _ in range(M_OPERATIONS):
                private_key.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())
            end = time.perf_counter()
            avg = (end - start) / M_OPERATIONS
            if avg < min_sign_time: min_sign_time = avg
        
        # Gerar uma assinatura válida apenas para usar na medição de verificação
        sig = private_key.sign(MESSAGE, padding.PKCS1v15(), hashes.SHA256())

        # Medir Verificação 
        min_verify_time = float('inf')
        for _ in range(N_ITERATIONS):
            start = time.perf_counter()
            for _ in range(M_OPERATIONS):
                public_key.verify(sig, MESSAGE, padding.PKCS1v15(), hashes.SHA256())
            end = time.perf_counter()
            avg = (end - start) / M_OPERATIONS
            if avg < min_verify_time: min_verify_time = avg

        print(f"  -> Sign: {min_sign_time*1000:.4f} ms | Verify: {min_verify_time*1000:.4f} ms")

        # --- RSA PSS ---
        print(f"Testing RSA-{bits} PSS:")
        
        # Configuração PSS
        pss_padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)

        # Medir Assinatura PSS
        min_sign_time = float('inf')
        for _ in range(N_ITERATIONS):
            start = time.perf_counter()
            for _ in range(M_OPERATIONS):
                private_key.sign(MESSAGE, pss_padding, hashes.SHA256())
            end = time.perf_counter()
            avg = (end - start) / M_OPERATIONS
            if avg < min_sign_time: min_sign_time = avg

        sig_pss = private_key.sign(MESSAGE, pss_padding, hashes.SHA256())

        # Medir Verificação PSS
        min_verify_time = float('inf')
        for _ in range(N_ITERATIONS):
            start = time.perf_counter()
            for _ in range(M_OPERATIONS):
                public_key.verify(sig_pss, MESSAGE, pss_padding, hashes.SHA256())
            end = time.perf_counter()
            avg = (end - start) / M_OPERATIONS
            if avg < min_verify_time: min_verify_time = avg

        print(f"  -> Sign: {min_sign_time*1000:.4f} ms | Verify: {min_verify_time*1000:.4f} ms\n")

if __name__ == "__main__":
    run_performance_test()