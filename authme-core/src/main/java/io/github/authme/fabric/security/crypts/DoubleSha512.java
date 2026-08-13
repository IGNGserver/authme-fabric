package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;

/** Double SHA-512: SHA-512(SHA-512(password)). Mirror of AuthMe's DOUBLE_SHA512. */
public class DoubleSha512 extends UnsaltedMethod {

    @Override
    public String computeHash(String password) {
        return HashUtils.sha512(HashUtils.sha512(password));
    }
}