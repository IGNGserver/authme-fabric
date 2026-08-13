package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.EncryptionMethod;
import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;

/**
 * Mirror of AuthMe's {@code SeparateSaltMethod}: the salt is stored in a separate database column
 * alongside the hash.
 */
public abstract class SeparateSaltMethod implements EncryptionMethod {

    public abstract String computeHash(String password, String salt, String name);

    @Override
    public HashedPassword computeHash(String password, String name) {
        String salt = generateSalt();
        return new HashedPassword(computeHash(password, salt, name), salt);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String hash = hashedPassword.getHash();
        String salt = hashedPassword.getSalt();
        if (hash == null || salt == null) {
            return false;
        }
        return HashUtils.isEqual(hash, computeHash(password, salt, name));
    }

    @Override
    public boolean hasSeparateSalt() {
        return true;
    }
}