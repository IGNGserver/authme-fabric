package io.github.authme.fabric.security;

/**
 * Mirror of AuthMe's {@code EncryptionMethod}. Implementations produce / verify password hashes that
 * are identical to those produced by the original plugin.
 */
public interface EncryptionMethod {

    /**
     * Hashes the given password, generating a salt as necessary.
     *
     * @param password the clear-text password
     * @param name     the player name (used by some legacy algorithms as part of the salt)
     * @return the hashed password (hash, and optionally a separate salt)
     */
    HashedPassword computeHash(String password, String name);

    /**
     * Hashes the given password with the given salt.
     *
     * @param password the clear-text password
     * @param salt     the salt to use
     * @param name     the player name
     * @return the hash (salt is not included in the returned wrapper for separate-salt methods)
     */
    String computeHash(String password, String salt, String name);

    /**
     * Verifies the given password against a stored hashed password.
     *
     * @param password      the clear-text password to check
     * @param hashedPassword the stored hash (and salt if {@link #hasSeparateSalt()} is true)
     * @param name          the player name
     * @return true if the password matches
     */
    boolean comparePassword(String password, HashedPassword hashedPassword, String name);

    /**
     * Generates a random salt if the algorithm uses one.
     *
     * @return the generated salt, or an empty string if the algorithm does not use a salt
     */
    String generateSalt();

    /**
     * Whether the algorithm stores the salt in a separate column from the hash.
     *
     * @return true if a separate salt column is required
     */
    boolean hasSeparateSalt();
}