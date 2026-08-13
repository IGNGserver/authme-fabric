package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.EncryptionMethod;
import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.security.RandomStringUtils;

/**
 * Mirror of AuthMe's {@code HexSaltedMethod}: a random hexadecimal salt is generated and embedded
 * inside the hash; no separate salt column is used.
 */
public abstract class HexSaltedMethod implements EncryptionMethod {

    public abstract int getSaltLength();

    public abstract String computeHash(String password, String salt, String name);

    @Override
    public HashedPassword computeHash(String password, String name) {
        String salt = generateSalt();
        return new HashedPassword(computeHash(password, salt, null));
    }

    @Override
    public abstract boolean comparePassword(String password, HashedPassword hashedPassword, String name);

    @Override
    public String generateSalt() {
        return RandomStringUtils.generateHex(getSaltLength());
    }

    @Override
    public boolean hasSeparateSalt() {
        return false;
    }
}