package io.github.authme.fabric.security;

/**
 * The result of a hash computation. The {@link #salt} is only present (non-null) for hashing methods
 * that store the salt in a separate database column (i.e. {@link EncryptionMethod#hasSeparateSalt()}
 * is true); otherwise the salt is embedded in {@link #hash}.
 */
public final class HashedPassword {

    private final String hash;
    private final String salt;

    public HashedPassword(String hash, String salt) {
        this.hash = hash;
        this.salt = salt;
    }

    public HashedPassword(String hash) {
        this(hash, null);
    }

    public String getHash() {
        return hash;
    }

    public String getSalt() {
        return salt;
    }
}