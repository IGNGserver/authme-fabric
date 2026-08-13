package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;
import io.github.authme.fabric.security.HashedPassword;

/**
 * SHA-256 with embedded hex salt. The default hash algorithm of AuthMe.
 * <p>
 * Format: {@code $SHA$<salt>$<sha256(sha256(password) + salt)>} where salt is a 16-character hex string.
 * This is byte-identical to AuthMe's {@code fr.xephi.authme.security.crypts.SHA256} (alias Sha256),
 * so an account database can be shared between this port and the original plugin.
 */
public class Sha256 extends HexSaltedMethod {

    @Override
    public String computeHash(String password, String salt, String name) {
        return "$SHA$" + salt + "$" + HashUtils.sha256(HashUtils.sha256(password) + salt);
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String hash = hashedPassword.getHash();
        if (hash == null) {
            return false;
        }
        String[] line = hash.split("\\$");
        return line.length == 4 && HashUtils.isEqual(hash, computeHash(password, line[2], name));
    }

    @Override
    public int getSaltLength() {
        return 16;
    }
}