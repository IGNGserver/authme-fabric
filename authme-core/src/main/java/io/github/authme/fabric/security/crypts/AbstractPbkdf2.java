package io.github.authme.fabric.security.crypts;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Common PBKDF2-HmacSHA256 derivation logic, mirroring AuthMe's {@code AbstractPbkdf2}. Uses
 * BouncyCastle's {@link PKCS5S2ParametersGenerator} so derived keys are identical to the original.
 */
public abstract class AbstractPbkdf2 extends HexSaltedMethod {

    protected final int numberOfRounds;

    protected AbstractPbkdf2(int numberOfRounds) {
        this.numberOfRounds = numberOfRounds;
    }

    protected byte[] deriveKey(String password, byte[] saltBytes, int iterations, int keyLength) {
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password.getBytes(StandardCharsets.UTF_8), saltBytes, iterations);
        return ((KeyParameter) gen.generateDerivedMacParameters(keyLength * 8)).getKey();
    }

    protected boolean verifyKey(String password, byte[] saltBytes, int iterations, byte[] expectedKey) {
        byte[] computed = deriveKey(password, saltBytes, iterations, expectedKey.length);
        return MessageDigest.isEqual(computed, expectedKey);
    }
}