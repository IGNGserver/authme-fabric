package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashedPassword;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * PBKDF2-HmacSHA256 with Base64-encoded salt and hash, mirroring AuthMe's {@code Pbkdf2Base64}.
 *
 * <p>Format: {@code pbkdf2$<iterations>$<base64-salt>$<base64-hash>}. Default rounds 120000, salt
 * 16 raw bytes, hash 32 raw bytes.
 */
public class Pbkdf2Base64 extends AbstractPbkdf2 {

    private static final int DEFAULT_ROUNDS = 120_000;
    private static final int SALT_BYTES = 16;
    private static final int HASH_BYTES = 32;
    private static final SecureRandom RANDOM = new SecureRandom();

    public Pbkdf2Base64() {
        this(DEFAULT_ROUNDS);
    }

    public Pbkdf2Base64(int rounds) {
        super(rounds);
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        byte[] saltBytes = Base64.getDecoder().decode(salt);
        byte[] hash = deriveKey(password, saltBytes, numberOfRounds, HASH_BYTES);
        return "pbkdf2$" + numberOfRounds + "$" + salt + "$" + Base64.getEncoder().encodeToString(hash);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String[] parts = hashedPassword.getHash().split("\\$");
        if (parts.length != 4) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] saltBytes = Base64.getDecoder().decode(parts[2]);
        byte[] expectedKey = Base64.getDecoder().decode(parts[3]);
        return verifyKey(password, saltBytes, iterations, expectedKey);
    }

    @Override
    public String generateSalt() {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    @Override
    public int getSaltLength() {
        return SALT_BYTES;
    }
}