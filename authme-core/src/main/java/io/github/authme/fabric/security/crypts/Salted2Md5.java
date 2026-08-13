package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.RandomStringUtils;

import static io.github.authme.fabric.security.HashUtils.md5;

/**
 * Salted double-MD5: {@code md5(md5(password) + salt)}. Salt length is configurable (AuthMe's
 * {@code doubleMD5SaltLength}, default 8). Separate salt column required.
 */
public class Salted2Md5 extends SeparateSaltMethod {

    private final int saltLength;

    public Salted2Md5() {
        this(8);
    }

    public Salted2Md5(int saltLength) {
        this.saltLength = saltLength;
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        return md5(md5(password) + salt);
    }

    @Override
    public String generateSalt() {
        return RandomStringUtils.generateHex(saltLength);
    }
}