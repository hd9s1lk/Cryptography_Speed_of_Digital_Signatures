import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.concurrent.TimeUnit;

public class RSAPerformance {

    // Configurações de Medição
    private static final int N_ITERATIONS = 5;
    private static final int M_OPERATIONS = 100;
    private static final byte[] MESSAGE = "CA_Trabalho_2".getBytes();

    public static void main(String[] args) throws Exception {
        // Adiciona a Bouncy Castle como provider de segurança
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("--- RSA Performance Test (Java: Bouncy Castle) ---");
        System.out.printf("N=%d, M=%d\n\n", N_ITERATIONS, M_OPERATIONS);

        int[] keySizes = { 1024, 2048, 4096 };

        for (int bits : keySizes) {
            System.out.printf("Generating %d-bit key... ", bits);
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
            keyGen.initialize(bits);
            KeyPair pair = keyGen.generateKeyPair();
            System.out.println("Done.");

            // ---RSA PKCS#1 v1.5 ---
            testAlgorithm("RSA PKCS#1 v1.5", "SHA256withRSA", pair, bits);

            // --- RSA PSS ---
            testAlgorithm("RSA PSS", "SHA256withRSA/PSS", pair, bits);
            System.out.println();
        }
    }

    private static void testAlgorithm(String algName, String algId, KeyPair pair, int bits) throws Exception {
        System.out.printf("Testing RSA-%d %s:\n", bits, algName);
        Signature sigEngine = Signature.getInstance(algId, "BC");

        // MEDIR ASSINATURA
        double minSignTime = Double.MAX_VALUE;

        for (int n = 0; n < N_ITERATIONS; n++) {
            long start = System.nanoTime();
            for (int m = 0; m < M_OPERATIONS; m++) {
                sigEngine.initSign(pair.getPrivate());
                sigEngine.update(MESSAGE);
                byte[] signature = sigEngine.sign();
            }
            long end = System.nanoTime();
            double avg = (double) (end - start) / M_OPERATIONS;
            if (avg < minSignTime) minSignTime = avg;
        }

        // Gera uma assinatura válida para a verificação
        sigEngine.initSign(pair.getPrivate());
        sigEngine.update(MESSAGE);
        byte[] validSig = sigEngine.sign();

        // MEDIR VERIFICAÇÃO
        double minVerifyTime = Double.MAX_VALUE;

        for (int n = 0; n < N_ITERATIONS; n++) {
            long start = System.nanoTime();
            for (int m = 0; m < M_OPERATIONS; m++) {
                sigEngine.initVerify(pair.getPublic());
                sigEngine.update(MESSAGE);
                boolean result = sigEngine.verify(validSig);
                if (!result) throw new RuntimeException("Verificação falhou!");
            }
            long end = System.nanoTime();
            double avg = (double) (end - start) / M_OPERATIONS;
            if (avg < minVerifyTime) minVerifyTime = avg;
        }

        System.out.printf("  -> Sign: %.4f ms | Verify: %.4f ms\n", 
            minSignTime / 1_000_000.0, minVerifyTime / 1_000_000.0);
    }
}