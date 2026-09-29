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

    /** Bounds for values parsed from a database hash; registration uses the configured values. */
    private static final int MAX_VERIFICATION_ITERATIONS = 10_000_000;
    private static final int MAX_SALT_BYTES = 1024;
    private static final int MAX_KEY_BYTES = 1024;

    protected final int numberOfRounds;

    protected AbstractPbkdf2(int numberOfRounds) {
        this.numberOfRounds = numberOfRounds;
    }

    protected byte[] deriveKey(String password, byte[] saltBytes, int iterations, int keyLength) {
        if (password == null || saltBytes == null || saltBytes.length > MAX_SALT_BYTES
            || iterations < 1 || iterations > MAX_VERIFICATION_ITERATIONS
            || keyLength < 1 || keyLength > MAX_KEY_BYTES) {
            throw new IllegalArgumentException("Unsafe PBKDF2 parameters");
        }
        PKCS5S2ParametersGenerator gen = new PKCS5S2ParametersGenerator(new SHA256Digest());
        gen.init(password.getBytes(StandardCharsets.UTF_8), saltBytes, iterations);
        return ((KeyParameter) gen.generateDerivedMacParameters(keyLength * 8)).getKey();
    }

    protected boolean verifyKey(String password, byte[] saltBytes, int iterations, byte[] expectedKey) {
        byte[] computed = deriveKey(password, saltBytes, iterations, expectedKey.length);
        return MessageDigest.isEqual(computed, expectedKey);
    }
}
