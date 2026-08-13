package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;

/** SHA-1 (unsalted). Mirror of AuthMe's deprecated SHA1. */
public class Sha1 extends UnsaltedMethod {

    @Override
    public String computeHash(String password) {
        return HashUtils.sha1(password);
    }
}