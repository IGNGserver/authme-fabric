package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.EncryptionMethod;
import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;

/**
 * Base class for hashing methods that embed no salt (or embed it in the hash itself), mirroring
 * AuthMe's {@code UnsaltedMethod}.
 */
public abstract class UnsaltedMethod implements EncryptionMethod {

    public abstract String computeHash(String password);

    @Override
    public HashedPassword computeHash(String password, String name) {
        return new HashedPassword(computeHash(password));
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        return computeHash(password);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String hash = hashedPassword.getHash();
        return hash != null && HashUtils.isEqual(hash, computeHash(password));
    }

    @Override
    public String generateSalt() {
        return "";
    }

    @Override
    public boolean hasSeparateSalt() {
        return false;
    }
}