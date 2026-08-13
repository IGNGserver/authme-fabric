package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.EncryptionMethod;
import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

import java.security.SecureRandom;

/**
 * BCrypt password hashing using BouncyCastle's {@link OpenBSDBCrypt}, mirroring AuthMe's
 * {@code BCryptHasher} / {@code BCrypt} (default BCrypt version "2a", log2 cost factor configurable,
 * default 10). Produces standard {@code $2a$<cost>$<22-char-salt><31-char-hash>} hashes of length 60.
 */
public class BCrypt implements EncryptionMethod {

    public static final int BYTES_IN_SALT = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final String version;
    private final int costFactor;

    public BCrypt() {
        this("2a", 10);
    }

    public BCrypt(String version, int costFactor) {
        this.version = version;
        this.costFactor = costFactor;
    }

    @Override
    public HashedPassword computeHash(String password, String name) {
        byte[] salt = new byte[BYTES_IN_SALT];
        RANDOM.nextBytes(salt);
        return new HashedPassword(OpenBSDBCrypt.generate(version, password.toCharArray(), salt, costFactor));
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        // BCrypt embeds its salt in the hash; given a raw salt is not normally provided.
        byte[] saltBytes = new byte[BYTES_IN_SALT];
        RANDOM.nextBytes(saltBytes);
        return OpenBSDBCrypt.generate(version, password.toCharArray(), saltBytes, costFactor);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String hash = hashedPassword.getHash();
        return hash != null && HashUtils.isValidBcryptHash(hash)
            && OpenBSDBCrypt.checkPassword(hash, password.toCharArray());
    }

    @Override
    public String generateSalt() {
        byte[] salt = new byte[BYTES_IN_SALT];
        RANDOM.nextBytes(salt);
        return new String(java.util.Base64.getEncoder().encode(salt));
    }

    @Override
    public boolean hasSeparateSalt() {
        return false;
    }
}