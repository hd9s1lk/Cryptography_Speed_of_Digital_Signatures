import java.security.*;
import java.security.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;

public class ECDSAPerformance {

    private static final int N_ITERATIONS = 5;
    private static final int M_OPERATIONS = 100;
    private static final byte[] MESSAGE = "CA_Trabalho_2".getBytes();

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("--- ECDSA Performance Test (Java: Bouncy Castle) ---");

        // Matriz de Testes (3 Tipos x 3 Tamanhos)
        runGroup("NIST P (Prime)", new String[]{"secp192r1", "secp256r1", "secp521r1"});
        runGroup("NIST K (Koblitz)", new String[]{"sect163k1", "sect233k1", "sect409k1"});
        runGroup("NIST B (Binary)", new String[]{"sect163r2", "sect283r1", "sect571r1"});
    }

    private static void runGroup(String groupName, String[] curves) {
        System.out.printf("\n=== Group: %s ===\n", groupName);
        for (String curveName : curves) {
            try {
                testCurve(curveName);
            } catch (Exception e) {
                System.out.printf("Curve: %-10s -> ERROR: %s\n", curveName, e.getMessage());
            }
        }
    }

    private static void testCurve(String curveName) throws Exception {
        // KeyGen específico para a curva pelo nome
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        KeyPair pair = g.generateKeyPair();
        
        Signature sigEngine = Signature.getInstance("SHA256withECDSA", "BC");

        //SIGN
        double minSign = Double.MAX_VALUE;
        for (int n = 0; n < N_ITERATIONS; n++) {
            long start = System.nanoTime();
            for (int m = 0; m < M_OPERATIONS; m++) {
                sigEngine.initSign(pair.getPrivate());
                sigEngine.update(MESSAGE);
                sigEngine.sign();
            }
            long end = System.nanoTime();
            double avg = (double)(end - start) / M_OPERATIONS;
            if (avg < minSign) minSign = avg;
        }

        // Assinatura para verificar
        sigEngine.initSign(pair.getPrivate());
        sigEngine.update(MESSAGE);
        byte[] sig = sigEngine.sign();

        // VERIFY
        double minVerify = Double.MAX_VALUE;
        for (int n = 0; n < N_ITERATIONS; n++) {
            long start = System.nanoTime();
            for (int m = 0; m < M_OPERATIONS; m++) {
                sigEngine.initVerify(pair.getPublic());
                sigEngine.update(MESSAGE);
                if(!sigEngine.verify(sig)) throw new RuntimeException("Fail");
            }
            long end = System.nanoTime();
            double avg = (double)(end - start) / M_OPERATIONS;
            if (avg < minVerify) minVerify = avg;
        }

        System.out.printf("Curve: %-10s -> Sign: %.4f ms | Verify: %.4f ms\n", 
            curveName, minSign / 1_000_000.0, minVerify / 1_000_000.0);
    }
}