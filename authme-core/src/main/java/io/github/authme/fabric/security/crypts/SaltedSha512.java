package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.RandomStringUtils;

/**
 * SHA-512 with a separate salt: {@code sha512(password + salt)}. Salt is a 32-character hex string.
 * Mirror of AuthMe's SaltedSha512 (separate salt column required).
 */
public class SaltedSha512 extends SeparateSaltMethod {

    @Override
    public String computeHash(String password, String salt, String name) {
        return HashUtils.sha512(password + salt);
    }

    @Override
    public String generateSalt() {
        return RandomStringUtils.generateHex(32);
    }
}