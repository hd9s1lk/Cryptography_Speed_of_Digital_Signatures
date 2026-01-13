#!/bin/bash


echo "========================================================"
echo "STARTING GLOBAL BENCHMARK (C, Java, Python)"
echo "========================================================"

# Run C Implementation
echo ""
echo "--------------------------------------------------------"
echo "[1/3] Running C tests (OpenSSL)..."
echo "--------------------------------------------------------"

# Enter the folder (adjust the name if different)
cd "C Implementation" || exit

# Compile and run ECDSA
echo " > Compiling and running ECDSA..."
gcc -o ecdsa_run ECDSA.c -lcrypto -lssl -Wno-deprecated-declarations
./ecdsa_run

# Compile and run RSA PKCS#1
echo " > Compiling and running RSA PKCS#1..."
gcc -o rsa_pkcs1_run "RSA_PKCS#1.c" -lcrypto -lssl -Wno-deprecated-declarations
./rsa_pkcs1_run

# Compile and run RSA PSS
echo " > Compiling and running RSA PSS..."
gcc -o rsa_pss_run RSA_PSS.c -lcrypto -lssl -Wno-deprecated-declarations
./rsa_pss_run

# Clean executables and return to root folder
rm *_run
cd ..

# Run Java Implementation
echo ""
echo "--------------------------------------------------------"
echo "[2/3] Running Java tests (Bouncy Castle)..."
echo "--------------------------------------------------------"

cd "Java Implementation" || exit

# Name of the JAR (confirm if this is the version in your folder)
JAR_FILE="bcprov-jdk18on-1.77.jar"

# Compile
echo " > Compiling Java files..."
javac -cp .:"$JAR_FILE" RSAPerformance.java ECDSAPerformance.java

# Run RSA
echo " > Running RSA Performance..."
java -cp .:"$JAR_FILE" RSAPerformance

# Run ECDSA
echo " > Running ECDSA Performance..."
java -cp .:"$JAR_FILE" ECDSAPerformance

# Clean .class files and return to root folder
rm *.class
cd ..

# Run Python Implementation
echo ""
echo "--------------------------------------------------------"
echo "[3/3] Running Python tests (Cryptography)..."
echo "--------------------------------------------------------"

cd "Python Implementation" || exit

# Check if the library is installed (install if necessary)
echo " > Checking dependencies..."
python3 -m pip install cryptography > /dev/null 2>&1

# Run RSA
echo " > Running RSA Manager..."
python3 RSA_Manager.py

# Run ECDSA
echo " > Running ECDSA Manager..."
python3 ECDSA_Manager.py

cd ..

echo ""
echo "========================================================"
echo "ALL TESTS COMPLETED SUCCESSFULLY!"
echo "========================================================"
