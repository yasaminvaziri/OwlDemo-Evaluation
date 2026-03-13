package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

/* * This benchmark implementation was adapted from the elliptic curve
 * implementation of the Owl protocol by Feng Hao (haofeng66@gmail.com).
 * License: MIT License
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
        long totalClientVerifyPass2ZKPs = 0;
        long totalClientComputeAlphaTime = 0;
        long totalClientComputeKandRTime = 0;

        // Accumulators for Server
        long totalServerRegTime = 0;
        long totalServerVerifyPass1ZKPs = 0;
        long totalServerPass2CompTime = 0;
        long totalServerVerifyAlphaZKP = 0;
        long totalServerComputeKTime = 0;
        long totalServerVerifyRTime = 0;

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

            tStart = System.nanoTime();
            boolean checkX1 = verifyZKP(G, X1, zkpX1.getV(), zkpX1.getr(), userName);
            boolean checkX2 = verifyZKP(G, X2, zkpX2.getV(), zkpX2.getr(), userName);
            if (isMeasuredRun) totalServerVerifyPass1ZKPs += (System.nanoTime() - tStart);
            if (!checkX1 || !checkX2) throw new RuntimeException("Server Verify Pass 1 Failed");

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

            tStart = System.nanoTime();
            boolean checkX3 = verifyZKP(G, X3, zkpX3.getV(), zkpX3.getr(), serverName);
            boolean checkX4 = verifyZKP(G, X4, zkpX4.getV(), zkpX4.getr(), serverName);
            boolean checkX4s = verifyZKP(GBeta, Beta, zkpX4s.getV(), zkpX4s.getr(), serverName);
            if (isMeasuredRun) totalClientVerifyPass2ZKPs += (System.nanoTime() - tStart);
            if (!checkX3 || !checkX4 || !checkX4s) throw new RuntimeException("Client Verify Pass 2 Failed");

            //  Compute Alpha and ZKP
            tStart = System.nanoTime();
            ECPoint GAlpha = X1.add(X3).add(X4);
            ECPoint Alpha = GAlpha.multiply(x2.multiply(piLogin).mod(n));
            SchnorrZKP zkpX2s = new SchnorrZKP();
            zkpX2s.generateZKP(GAlpha, n, x2.multiply(piLogin).mod(n), Alpha, userName);
            if (isMeasuredRun) totalClientComputeAlphaTime += (System.nanoTime() - tStart);

            // Compute Raw Key K and r
            tStart = System.nanoTime();
            ECPoint rawClientKey = Beta.subtract(X4.multiply(x2.multiply(piLogin).mod(n))).multiply(x2);
            BigInteger hTranscript = getSHA256(rawClientKey, userName, X1, X2, zkpX1, zkpX2, serverName,
                    X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);
            BigInteger rValue = x1.subtract(tLogin.multiply(hTranscript)).mod(n);
            if (isMeasuredRun) totalClientComputeKandRTime += (System.nanoTime() - tStart);


            // =========================================================
            // LOGIN - PASS 3 Verifications (Server)
            // =========================================================

            tStart = System.nanoTime();
            boolean checkX2s = verifyZKP(GAlpha, Alpha, zkpX2s.getV(), zkpX2s.getr(), userName);
            if (isMeasuredRun) totalServerVerifyAlphaZKP += (System.nanoTime() - tStart);
            if (!checkX2s) throw new RuntimeException("Server Verify Pass 3 Failed");

            //  Compute Raw Key K
            tStart = System.nanoTime();
            ECPoint rawServerKey = Alpha.subtract(X2.multiply(x4.multiply(pi).mod(n))).multiply(x4);
            if (isMeasuredRun) totalServerComputeKTime += (System.nanoTime() - tStart);

            // Verify r
            tStart = System.nanoTime();
            BigInteger hServer = getSHA256(rawServerKey, userName, X1, X2, zkpX1, zkpX2, serverName,
                    X3, X4, zkpX3, zkpX4, Beta, zkpX4s, Alpha, zkpX2s).mod(n);
            ECPoint expectedX1 = ECAlgorithms.shamirsTrick(G, rValue, T, hServer.mod(n));
            boolean isRValid = expectedX1.equals(X1);
            if (isMeasuredRun) totalServerVerifyRTime += (System.nanoTime() - tStart);
            if (!isRValid) throw new RuntimeException("Server Authentication Failed");
        }

        double div = iterations * 1_000_000.0;

        System.out.println("\n--- BENCHMARK RESULTS (Averages over " + iterations + " iterations) ---");

        System.out.println("\nREGISTRATION COSTS:");
        System.out.printf("Client Compute T:                                  %.4f ms\n", (totalClientRegTime / div));
        System.out.printf("Server Compute X3, \\Pi_3:                          %.4f ms\n", (totalServerRegTime / div));

        System.out.println("\nLOGIN - CLIENT:");
        System.out.printf("Pass 1 Compute X1, X2, \\Pi_1, \\Pi_2:               %.4f ms\n", (totalClientPass1Time / div));
        System.out.printf("Pass 2 Verify server ZKPs (\\Pi_3, \\Pi_4, \\Pi_b):   %.4f ms\n", (totalClientVerifyPass2ZKPs / div));
        System.out.printf("Pass 3 Compute alpha, \\Pi_a:                       %.4f ms\n", (totalClientComputeAlphaTime / div));
        System.out.printf("Pass 3 Compute K, r:                               %.4f ms\n", (totalClientComputeKandRTime / div));
        double clientTotal = (totalClientPass1Time + totalClientVerifyPass2ZKPs + totalClientComputeAlphaTime + totalClientComputeKandRTime) / div;
        System.out.printf("Client Total:                                      %.4f ms\n", clientTotal);

        System.out.println("\nLOGIN - SERVER:");
        System.out.printf("Pass 1 Verify client ZKPs (\\Pi_1, \\Pi_2):         %.4f ms\n", (totalServerVerifyPass1ZKPs / div));
        System.out.printf("Pass 2 Compute X4, \\Pi_4, beta, \\Pi_b:             %.4f ms\n", (totalServerPass2CompTime / div));
        System.out.printf("Pass 3 Verify client ZKP (\\Pi_a):                  %.4f ms\n", (totalServerVerifyAlphaZKP / div));
        System.out.printf("Pass 3 Compute K:                                  %.4f ms\n", (totalServerComputeKTime / div));
        System.out.printf("Pass 3 Verify r:                                   %.4f ms\n", (totalServerVerifyRTime / div));
        double serverTotal = (totalServerVerifyPass1ZKPs + totalServerPass2CompTime + totalServerVerifyAlphaZKP + totalServerComputeKTime + totalServerVerifyRTime) / div;
        System.out.printf("Server Total:                                      %.4f ms\n", serverTotal);
    }

    public BigInteger getSHA256(Object... args) {
        MessageDigest sha256 = null;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
            for (Object arg : args) {
                if (arg instanceof ECPoint) {
                    ECPoint p = (ECPoint) arg;
                    sha256.update(java.nio.ByteBuffer.allocate(4).putInt(p.getEncoded(true).length).array());
                    sha256.update(p.getEncoded(true));
                } else if (arg instanceof String) {
                    String s = (String) arg;
                    sha256.update(java.nio.ByteBuffer.allocate(4).putInt(s.getBytes().length).array());
                    sha256.update(s.getBytes());
                } else if (arg instanceof BigInteger) {
                    BigInteger i = (BigInteger) arg;
                    sha256.update(java.nio.ByteBuffer.allocate(4).putInt(i.toByteArray().length).array());
                    sha256.update(i.toByteArray());
                } else if (arg instanceof SchnorrZKP) {
                    SchnorrZKP zkp = (SchnorrZKP) arg;
                    sha256.update(java.nio.ByteBuffer.allocate(4).putInt(zkp.getV().getEncoded(true).length).array());
                    sha256.update(zkp.getV().getEncoded(true));
                    sha256.update(java.nio.ByteBuffer.allocate(4).putInt(zkp.getr().toByteArray().length).array());
                    sha256.update(zkp.getr().toByteArray());
                } else {
                    throw new IllegalArgumentException("Invalid object type");
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
        if (V.equals(expectedV)) return true;
        return false;
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
        } catch(Exception e) {
            return false;
        }
        if (X.multiply(coFactor).isInfinity()) return false;
        return true;
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