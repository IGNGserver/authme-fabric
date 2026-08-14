package io.github.authme.fabric.security;

/**
 * Hash algorithms supported by this AuthMe port. Names mirror AuthMe's
 * {@code fr.xephi.authme.security.HashAlgorithm} enum so the same {@code settings.security.passwordHash}
 * values from an AuthMe config.yml are accepted.
 */
public enum HashAlgorithm {
    ARGON2,
    ARGON2ID,
    BCRYPT,
    BCRYPT2Y,
    CUSTOM,
    CMW,
    CRAZYCRYPT1,
    DOUBLE_SHA512,
    DOUBLEMD5,
    IPB3,
    IPB4,
    JOOMLA,
    MD5,
    MD5VB,
    MYBB,
    PBKDF2,
    PBKDF2BASE64,
    PBKDF2DJANGO,
    PHPBB,
    PHPFUSION,
    PLAINTEXT,
    ROYALAUTH,
    SALTED2MD5,
    SALTEDSHA256,
    SALTEDSHA512,
    SHA1,
    SHA256,
    SHA512,
    SMF,
    TWO_FACTOR,
    WBB3,
    WBB4,
    WORDPRESS,
    XFBCRYPT;

    /** Parse the value as AuthMe does (case-insensitive), defaulting to SHA256. */
    public static HashAlgorithm parse(String value) {
        if (value == null || value.isBlank()) {
            return SHA256;
        }
        try {
            return HashAlgorithm.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            return SHA256;
        }
    }
}
