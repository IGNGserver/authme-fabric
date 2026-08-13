package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashUtils;

/** MD5 (unsalted). Mirror of AuthMe's deprecated MD5. */
public class Md5 extends UnsaltedMethod {

    @Override
    public String computeHash(String password) {
        return HashUtils.md5(password);
    }
}