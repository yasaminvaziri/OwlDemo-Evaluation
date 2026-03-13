package org.example;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/* * This benchmark implementation was adapted from the elliptic curve
 * implementation of the Owl protocol by Feng Hao (haofeng66@gmail.com).
 * * Original source: https://github.com/haofeng66/OwlDemo/blob/main/EllipticCurveOwlDemo.java
 * An Augmented Password-Authenticated Key Exchange Scheme," FC, 2024
 * * License: MIT License
 */

public class Benchmark {

    private ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
    private ECCurve.Fp ecCurve = (ECCurve.Fp)ecSpec.getCurve();
    private BigInteger q = ecCurve.getQ();
    private BigInteger coFactor = ecSpec.getH();
    private BigInteger n = ecSpec.getN();
    private ECPoint G = ecSpec.getG();

    private String userName = "Alice";
    private String serverName = "Server";
    private String passwordRegister = "deadbeef";
    private String passwordLogin = "deadbeef";

    public static void main(String args[]) {
        Benchmark test = new Benchmark();
        test.runBenchmark(100, 1000);
    }

    private void runBenchmark(int warmups, int iterations) {
        System.out.println("Starting benchmark...");
        System.out.println("Warm-up iterations: " + warmups);
        System.out.println("Measured iterations: " + iterations);

        // Accumulators for Client
        long totalClientRegTime = 0;
        long totalClientPass1Time = 0;
        long totalClientVerifyX3Time = 0;
        long totalClientVerifyX4Time = 0;
        long totalClientVerifyX4sTime = 0;
        long totalClientPass3CompTime = 0;
        long totalClientFinalVerifyTime = 0;

        // Accumulators for Server
        long totalServerRegTime = 0;
        long totalServerVerifyX1Time = 0;
        long totalServerVerifyX2Time = 0;
        long totalServerPass2CompTime = 0;
        long totalServerVerifyX2sTime = 0;
        long totalServerPass4CompTime = 0;

        int totalRuns = warmups + iterations;

        for (int i = 0; i < totalRuns; i++) {
            boolean isMeasuredRun = (i >= warmups);
            long tStart;

            // =========================================================
            // REGISTRATION
            // =========================================================

            // --- CLIENT REGISTRATION ---
            tStart = System.nanoTime();
            BigInteger t = getSHA256(userName, passwordRegister).mod(n);
            BigInteger pi = getSHA256(t).mod(n);
            ECPoint T = G.multiply(t);
            if (isMeasuredRun) totalClientRegTime += (System.nanoTime() - tStart);

            if (userName.equals(serverName) || pi.compareTo(BigInteger.ONE)==-1 || pi.compareTo(n.subtract(BigInteger.ONE)) == 1 || !isValidPublicKey(T)) {
                throw new RuntimeException("Client Registration Checks Failed");
            }

            // --- SERVER REGISTRATION ---
            tStart = System.nanoTime();
            BigInteger x3 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
            ECPoint X3 = G.multiply(x3);
            SchnorrZKP zkpX3 = new SchnorrZKP();
            zkpX3.generateZKP(G, n, x3, X3, serverName);
            if (isMeasuredRun) totalServerRegTime += (System.nanoTime() - tStart);


            // =========================================================
            // LOGIN - PASS 1 (Client)
            // =========================================================

            // --- CLIENT COMPUTATION ---
            tStart = System.nanoTime();
            BigInteger tLogin = getSHA256(userName, passwordLogin).mod(n);
            BigInteger piLogin = getSHA256(tLogin).mod(n);

            BigInteger x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
            BigInteger x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());

            ECPoint X1 = G.multiply(x1);
            SchnorrZKP zkpX1 = new SchnorrZKP();
            zkpX1.generateZKP(G, n, x1, X1, userName);

            ECPoint X2 = G.multiply(x2);
            SchnorrZKP zkpX2 = new SchnorrZKP();
            zkpX2.generateZKP(G, n, x2, X2, userName);
            if (isMeasuredRun) totalClientPass1Time += (System.nanoTime() - tStart);


            // =========================================================
            // LOGIN - PASS 2 (Server)
            // =========================================================

            // --- SERVER VERIFICATION ---
            tStart = System.nanoTime();
            boolean checkX1 = verifyZKP(G, X1, zkpX1.getV(), zkpX1.getr(), userName);
            if (isMeasuredRun) totalServerVerifyX1Time += (System.nanoTime() - tStart);

            tStart = System.nanoTime();
            boolean checkX2 = verifyZKP(G, X2, zkpX2.getV(), zkpX2.getr(), userName);
            if (isMeasuredRun) totalServerVerifyX2Time += (System.nanoTime() - tStart);

            if (!checkX1 || !checkX2) throw new RuntimeException("Server Verify Pass 1 Failed");

            // --- SERVER COMPUTATION ---
            tStart = System.nanoTime();
            BigInteger x4 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
            ECPoint X4 = G.multiply(x4);
            SchnorrZKP zkpX4 = new SchnorrZKP();
            zkpX4.generateZKP(G, n, x4, X4, serverName);

            ECPoint GBeta = X1.add(X2).add(X3);
            ECPoint Beta = GBeta.multiply(x4.multiply(pi).mod(n));

            SchnorrZKP zkpX4s = new SchnorrZKP();
            zkpX4s.generateZKP(GBeta, n, x4.multiply(pi).mod(n), Beta, serverName);
            if (isMeasuredRun) totalServerPass2CompTime += (System.nanoTime() - tStart);


            // =========================================================
            // LOGIN - PASS 3 (Client)
            // =========================================================

            // --- CLIENT VERIFICATION ---
            tStart = System.nanoTime();
            boolean checkX3 = verifyZKP(G, X3, zkpX3.getV(), zkpX3.getr(), serverName);
            if (isMeasuredRun) totalClientVerifyX3Time += (System.nanoTime() - tStart);

            tStart = System.nanoTime();
            boolean checkX4 = verifyZKP(G, X4, zkpX4.getV(), zkpX4.getr(), serverName);
            if (isMeasuredRun) totalClientVerifyX4Time += (System.nanoTime() - tStart);

            tStart = System.nanoTime();
            boolean checkX4s = verifyZKP(GBeta, Beta, zkpX4s.getV(), zkpX4s.getr(), serverName);
            if (isMeasuredRun) totalClientVerifyX4sTime += (System.nanoTime() - tStart);

            if (!checkX3 || !checkX4 || !checkX4s) throw new RuntimeException("Client Verify Pass 2 Failed");

            // --- CLIENT COMPUTATION ---
            tStart = System.nanoTime();
            ECPoint GAlpha = X1.add(X3).add(X4);
            ECPoint Alpha = GAlpha.multiply(x2.multiply(piLogin).mod(n));

            SchnorrZKP zkpX2s = new SchnorrZKP();
            zkpX2s.generateZKP(GAlpha, n, x2.multiply(piLogin).mod(n), Alpha, userName);

            ECPoint rawClientKey = Beta.subtract(X4.multiply(x2.multiply(piLogin).mod(n))).multiply(x2);
            BigInteger clientSessionKey = deriveKey(rawClientKey, "SESS");
            BigInteger clientKCKey = deriveKey(rawClientKey, "KC");

            BigInteger hTranscript = getSHA256(rawClientKey, userName, X1, X2, zkpX1, zkpX2, serverName,
                    X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);

            BigInteger rValue = x1.subtract(tLogin.multiply(hTranscript)).mod(n);
            BigInteger clientKCTag = this.deriveHMACTag(clientKCKey, "KC_1_U", userName, serverName, X1, X2, X3, X4);
            if (isMeasuredRun) totalClientPass3CompTime += (System.nanoTime() - tStart);


            // =========================================================
            // LOGIN - PASS 4 (Server & Final Client)
            // =========================================================

            // --- SERVER VERIFICATION ---
            tStart = System.nanoTime();
            boolean checkX2s = verifyZKP(GAlpha, Alpha, zkpX2s.getV(), zkpX2s.getr(), userName);
            if (isMeasuredRun) totalServerVerifyX2sTime += (System.nanoTime() - tStart);

            if (!checkX2s) throw new RuntimeException("Server Verify Pass 3 Failed");

            // --- SERVER COMPUTATION ---
            tStart = System.nanoTime();
            ECPoint rawServerKey = Alpha.subtract(X2.multiply(x4.multiply(pi).mod(n))).multiply(x4);
            BigInteger serverSessionKey = deriveKey(rawServerKey, "SESS");
            BigInteger serverKCKey = deriveKey(rawServerKey, "KC");

            BigInteger hServer = getSHA256(rawServerKey, userName, X1, X2, zkpX1, zkpX2, serverName,
                    X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);


            ECPoint expectedX1 = ECAlgorithms.shamirsTrick(G, rValue, T, hServer.mod(n));
            boolean isRValid = expectedX1.equals(X1);
            BigInteger clientKCTag2 = this.deriveHMACTag(serverKCKey, "KC_1_U", userName, serverName, X1, X2, X3, X4);
            boolean isKCTagValid = clientKCTag2.equals(clientKCTag);

            BigInteger serverKCTag = deriveHMACTag(serverKCKey, "KC_1_V", serverName, userName, X3, X4, X1, X2);
            if (isMeasuredRun) totalServerPass4CompTime += (System.nanoTime() - tStart);

            if (!isRValid || !isKCTagValid) throw new RuntimeException("Server Authentication/KC Failed");

            // --- FINAL CLIENT VERIFICATION ---
            tStart = System.nanoTime();
            BigInteger serverKCTag2FromClient = this.deriveHMACTag(clientKCKey, "KC_1_V", serverName, userName, X3, X4, X1, X2);
            boolean finalClientCheck = serverKCTag2FromClient.equals(serverKCTag);
            if (isMeasuredRun) totalClientFinalVerifyTime += (System.nanoTime() - tStart);

            if (!finalClientCheck) throw new RuntimeException("Final Client KC Failed");

        }

        // Output Results
        double div = iterations * 1_000_000.0; // Convert to ms and calculate mean

        System.out.println("\n--- BENCHMARK RESULTS (Averages over " + iterations + " iterations) ---");

        System.out.println("\nREGISTRATION COSTS:");
        System.out.printf("Client Registration (Computing T):                 %.4f ms\n", (totalClientRegTime / div));
        System.out.printf("Server Registration (Computing X3, ZKP):           %.4f ms\n", (totalServerRegTime / div));

        System.out.println("\nLOGIN - CLIENT COSTS:");
        System.out.printf("Pass 1 Computation (X1, X2, ZKPs):                 %.4f ms\n", (totalClientPass1Time / div));
        System.out.printf("Pass 3 Verify Server ZKP{X3}:                      %.4f ms\n", (totalClientVerifyX3Time / div));
        System.out.printf("Pass 3 Verify Server ZKP{X4}:                      %.4f ms\n", (totalClientVerifyX4Time / div));
        System.out.printf("Pass 3 Verify Server ZKP{Beta}:                    %.4f ms\n", (totalClientVerifyX4sTime / div));
        System.out.printf("Pass 3 Computation (Alpha, r, KDF, MAC):           %.4f ms\n", (totalClientPass3CompTime / div));
        System.out.printf("Pass 4 Final Client Verify (serverKCTag):          %.4f ms\n", (totalClientFinalVerifyTime / div));

        System.out.println("\nLOGIN - SERVER COSTS:");
        System.out.printf("Pass 2 Verify Client ZKP{X1}:                      %.4f ms\n", (totalServerVerifyX1Time / div));
        System.out.printf("Pass 2 Verify Client ZKP{X2}:                      %.4f ms\n", (totalServerVerifyX2Time / div));
        System.out.printf("Pass 2 Computation (X4, Beta, ZKPs):               %.4f ms\n", (totalServerPass2CompTime / div));
        System.out.printf("Pass 4 Verify Client ZKP{Alpha}:                   %.4f ms\n", (totalServerVerifyX2sTime / div));
        System.out.printf("Pass 4 Computation (r Check, KDF, MACs):           %.4f ms\n", (totalServerPass4CompTime / div));


    }

    public String pointToHex(ECPoint X) {
        return new BigInteger(X.getEncoded(true)).toString(16);
    }

    public BigInteger getSHA256(Object... args) {
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            for (Object arg : args) {
                if (arg instanceof ECPoint) {
                    ECPoint p = (ECPoint) arg;
                    sha256.update(intTo4Bytes(p.getEncoded(true).length));
                    sha256.update(p.getEncoded(true));
                } else if (arg instanceof String) {
                    String s = (String) arg;
                    sha256.update(intTo4Bytes(s.getBytes().length));
                    sha256.update(s.getBytes());
                } else if (arg instanceof BigInteger) {
                    BigInteger i = (BigInteger) arg;
                    sha256.update(intTo4Bytes(i.toByteArray().length));
                    sha256.update(i.toByteArray());
                } else if (arg instanceof SchnorrZKP) {
                    SchnorrZKP zkp = (SchnorrZKP) arg;
                    sha256.update(intTo4Bytes(zkp.getV().getEncoded(true).length));
                    sha256.update(zkp.getV().getEncoded(true));
                    sha256.update(intTo4Bytes(zkp.getr().toByteArray().length));
                    sha256.update(zkp.getr().toByteArray());
                } else {
                    throw new IllegalArgumentException("Invalid object type passed to getSHA256");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new BigInteger(1, sha256.digest());
    }

    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, String userID) {
        BigInteger h = getSHA256(generator, V, X, userID);
        ECPoint expectedV = ECAlgorithms.shamirsTrick(generator, r, X, h.mod(n));
        if (!isValidPublicKey(X)) return false;
        if (V.equals(expectedV)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean isValidPublicKey(ECPoint X) {
        if (X.isInfinity()) return false;
        if (X.normalize().getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.normalize().getXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
                X.normalize().getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.normalize().getYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1) {
            return false;
        }
        try {
            ecCurve.decodePoint(X.getEncoded(true));
        }catch(Exception e){
            return false;
        }
        if (X.multiply(coFactor).isInfinity()) return false;
        return true;
    }

    public byte[] intTo4Bytes (int length) {
        return ByteBuffer.allocate(4).putInt(length).array();
    }

    public BigInteger deriveKey (ECPoint rawKey, String otherInput) {
        return getSHA256(rawKey, otherInput);
    }

    public BigInteger deriveHMACTag(BigInteger key, String messageString, String senderID,
                                    String receiverID, ECPoint senderKey1, ECPoint senderKey2, ECPoint receiverKey1,
                                    ECPoint receiverKey2) {
        BigInteger macTag = null;
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.toByteArray(), "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(secretKeySpec);
            mac.update(intTo4Bytes(messageString.getBytes().length));
            mac.update(messageString.getBytes());
            mac.update(intTo4Bytes(senderID.getBytes().length));
            mac.update(senderID.getBytes());
            mac.update(intTo4Bytes(receiverID.getBytes().length));
            mac.update(receiverID.getBytes());
            mac.update(intTo4Bytes(senderKey1.getEncoded(true).length));
            mac.update(senderKey1.getEncoded(true));
            mac.update(intTo4Bytes(senderKey2.getEncoded(true).length));
            mac.update(senderKey2.getEncoded(true));
            mac.update(intTo4Bytes(receiverKey1.getEncoded(true).length));
            mac.update(receiverKey1.getEncoded(true));
            mac.update(intTo4Bytes(receiverKey2.getEncoded(true).length));
            mac.update(receiverKey2.getEncoded(true));
            macTag = new BigInteger(1, mac.doFinal());
        }catch(Exception e) {
            e.printStackTrace();
        }
        return macTag;
    }

    private class SchnorrZKP {
        private ECPoint V = null;
        private BigInteger r = null;
        private SchnorrZKP () {}

        private void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, String userID) {
            BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), new SecureRandom());
            V = generator.multiply(v);
            BigInteger h = getSHA256(generator, V, X, userID);
            r = v.subtract(x.multiply(h)).mod(n);
        }

        private ECPoint getV() { return V; }
        private BigInteger getr() { return r; }
    }
}