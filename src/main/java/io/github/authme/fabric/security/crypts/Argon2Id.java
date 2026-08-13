package io.github.authme.fabric.security.crypts;

import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Argon2id variant of {@link Argon2}; uses {@code ARGON2_id} and the {@code $argon2id$} prefix.
 * Mirror of AuthMe's {@code Argon2Id}.
 */
public class Argon2Id extends Argon2 {

    @Override
    protected int getType() {
        return Argon2Parameters.ARGON2_id;
    }

    @Override
    protected String getPrefix() {
        return "argon2id";
    }
}