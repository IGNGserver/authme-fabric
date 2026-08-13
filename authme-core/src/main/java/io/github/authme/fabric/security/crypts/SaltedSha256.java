package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.RandomStringUtils;

/**
 * SHA-256 with a separate salt: {@code sha256(password + salt)}. Salt is a 32-character hex string.
 * Mirror of AuthMe's SaltedSha256 (separate salt column required).
 */
public class SaltedSha256 extends SeparateSaltMethod {

    @Override
    public String computeHash(String password, String salt, String name) {
        return HashUtils.sha256(password + salt);
    }

    @Override
    public String generateSalt() {
        return RandomStringUtils.generateHex(32);
    }
}