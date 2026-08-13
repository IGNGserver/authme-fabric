package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;

/** SHA-512 (unsalted). Mirror of AuthMe's deprecated SHA512. */
public class Sha512 extends UnsaltedMethod {

    @Override
    public String computeHash(String password) {
        return HashUtils.sha512(password);
    }
}