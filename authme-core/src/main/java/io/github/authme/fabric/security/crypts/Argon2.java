package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.EncryptionMethod;
import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Argon2i password hashing via BouncyCastle, mirroring AuthMe's {@code Argon2} exactly.
 *
 * <p>Format: {@code $argon2i$v=19$m=65536,t=2,p=1$<base64-salt>$<base64-hash>}. Salt is 16 raw bytes,
 * hash is 32 raw bytes.
 */
public class Argon2 implements EncryptionMethod {

    protected static final int ITERATIONS = 2;
    protected static final int MEMORY_KB = 65536;
    protected static final int PARALLELISM = 1;
    protected static final int SALT_BYTES = 16;
    protected static final int HASH_BYTES = 32;

    private final SecureRandom random = new SecureRandom();

    protected int getType() {
        return Argon2Parameters.ARGON2_i;
    }

    protected String getPrefix() {
        return "argon2i";
    }

    @Override
    public HashedPassword computeHash(String password, String name) {
        return new HashedPassword(computeHash(password, "", name));
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        byte[] saltBytes = new byte[SALT_BYTES];
        random.nextBytes(saltBytes);
        byte[] hash = derive(password.toCharArray(), saltBytes, ITERATIONS, MEMORY_KB, PARALLELISM, HASH_BYTES, getType());
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        return "$" + getPrefix() + "$v=19$m=" + MEMORY_KB + ",t=" + ITERATIONS + ",p=" + PARALLELISM
            + "$" + enc.encodeToString(saltBytes)
            + "$" + enc.encodeToString(hash);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String[] parts = hashedPassword.getHash().split("\\$");
        if (parts.length != 6 || !getPrefix().equals(parts[1])) {
            return false;
        }
        try {
            int[] params = parseParams(parts[3]);
            byte[] salt = decodeNoPadding(parts[4]);
            byte[] expected = decodeNoPadding(parts[5]);
            byte[] computed = derive(password.toCharArray(), salt, params[1], params[0], params[2], expected.length, getType());
            return MessageDigest.isEqual(computed, expected);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String generateSalt() {
        return "";
    }

    @Override
    public boolean hasSeparateSalt() {
        return false;
    }

    protected static byte[] derive(char[] password, byte[] salt, int iterations, int memoryKb, int parallelism, int hashLen, int type) {
        Argon2Parameters params = new Argon2Parameters.Builder(type)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memoryKb)
            .withParallelism(parallelism)
            .withSalt(salt)
            .build();
        Argon2BytesGenerator generator = new Argon2BytesGenerator();
        generator.init(params);
        byte[] result = new byte[hashLen];
        generator.generateBytes(password, result);
        return result;
    }

    private static int[] parseParams(String paramStr) {
        int[] result = new int[3];
        for (String kv : paramStr.split(",")) {
            String[] pair = kv.split("=");
            int v = Integer.parseInt(pair[1]);
            switch (pair[0]) {
                case "m": result[0] = v; break;
                case "t": result[1] = v; break;
                case "p": result[2] = v; break;
                default: break;
            }
        }
        return result;
    }

    private static byte[] decodeNoPadding(String s) {
        switch (s.length() % 4) {
            case 2: s += "=="; break;
            case 3: s += "="; break;
            default: break;
        }
        return Base64.getDecoder().decode(s);
    }
}