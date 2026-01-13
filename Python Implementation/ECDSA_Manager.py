import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes

N_ITERATIONS = 5
M_OPERATIONS = 100
MESSAGE = b"CA_Trabalho_2"



# Definição da Matriz de Testes (3 Tipos x 3 Tamanhos)
CURVES = {
    "NIST P (Prime)": [
        ("P-192", ec.SECP192R1()), # Pequena
        ("P-256", ec.SECP256R1()), # Média
        ("P-521", ec.SECP521R1())  # Grande
    ],
    "NIST K (Koblitz)": [
        ("K-163", ec.SECT163K1()), 
        ("K-233", ec.SECT233K1()), 
        ("K-409", ec.SECT409K1())
    ],
    "NIST B (Binary)": [
        ("B-163", ec.SECT163R2()), 
        ("B-283", ec.SECT283R1()), 
        ("B-571", ec.SECT571R1())
    ]
}

def run_ecdsa_test():
    print(f"--- ECDSA Performance Test (Library: cryptography) ---")
    
    for group_name, curves_list in CURVES.items():
        print(f"\n=== Group: {group_name} ===")
        
        for name, curve_oid in curves_list:
            try:
                # Keygen
                private_key = ec.generate_private_key(curve_oid)
                public_key = private_key.public_key()
                
                # Medir Assinatura
                min_sign_time = float('inf')
                for _ in range(N_ITERATIONS):
                    start = time.perf_counter()
                    for _ in range(M_OPERATIONS):
                        private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))
                    end = time.perf_counter()
                    avg = (end - start) / M_OPERATIONS
                    if avg < min_sign_time: min_sign_time = avg
                
                # Criar assinatura para verificar
                sig = private_key.sign(MESSAGE, ec.ECDSA(hashes.SHA256()))

                # Medir Verificação
                min_verify_time = float('inf')
                for _ in range(N_ITERATIONS):
                    start = time.perf_counter()
                    for _ in range(M_OPERATIONS):
                        public_key.verify(sig, MESSAGE, ec.ECDSA(hashes.SHA256()))
                    end = time.perf_counter()
                    avg = (end - start) / M_OPERATIONS
                    if avg < min_verify_time: min_verify_time = avg
                
                print(f"Curve: {name: <10} -> Sign: {min_sign_time*1000:.4f} ms | Verify: {min_verify_time*1000:.4f} ms")
            
            except Exception as e:
                # Se a biblioteca não suportar alguma curva específica (pode acontecer em versões antigas)
                print(f"Curve: {name: <10} -> ERROR or Not Supported by this lib version.")

if __name__ == "__main__":
    run_ecdsa_test()