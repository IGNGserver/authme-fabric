package io.github.authme.fabric.security.crypts;

/**
 * Plain-text "hashing": stores the password verbatim. Only provided for legacy AuthMe compatibility;
 * never recommended.
 */
public class Plain extends UnsaltedMethod {

    @Override
    public String computeHash(String password) {
        return password;
    }
}