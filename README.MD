# Project 2: The Speed of Digital Signatures Applied Cryptography - MSc Cybersecurity

Authors: Pedro Costa (130720) Henrique Dias (131144)

## Quick Start (Automatic)

To run all benchmarks sequentially across all languages (C, Java, Python), simply run the provided shell script in the root directory:

```./run_all.sh```

This script will compile source codes, handle classpaths, and execute the performance measurements automatically.

## Manual Instructions

If you prefer to run each language individually, follow the instructions below.

### C Implementation (OpenSSL) 

Requirements: ```gcc, openssl (libssl-dev)```

Navigate to the C Implementation folder: ```cd "C Implementation"```

To run RSA PKCS#1: ```gcc -o rsa_pkcs1 "RSA_PKCS#1.c" -lcrypto -lssl``` and then ```./rsa_pkcs1```

To run RSA PSS: ```gcc -o rsa_pss RSA_PSS.c -lcrypto -lssl``` and then ```./rsa_pss```

To run ECDSA: ```gcc -o ecdsa ECDSA.c -lcrypto -lssl``` and then ```./ecdsa```

### Java Implementation (Bouncy Castle) 

Requirements: ```Java JDK (tested on JDK 17+)```
The library ```bcprov-jdk18on-1.77.jar``` 

Navigate to the Java Implementation folder:
cd "Java Implementation" (make sure bcprov-jdk18on-1.77.jar is in this folder)

Compile and run RSA:
```javac -cp .:bcprov-jdk18on-1.77.jar RSAPerformance.java``` and then
```java  -cp .:bcprov-jdk18on-1.77.jar RSAPerformance```

Compile and run ECDSA:
```javac -cp .:bcprov-jdk18on-1.77.jar ECDSAPerformance.java``` and then
```java  -cp .:bcprov-jdk18on-1.77.jar ECDSAPerformance```

### Python Implementation (Cryptography Lib) 

Requirements: ```python3, pip```

Navigate to the Python Implementation folder: ```cd "Python Implementation"```

Install the required library: ```pip install cryptography```

Run the benchmarks: ```python3 RSA_Manager.py python3 ECDSA_Manager.py```
