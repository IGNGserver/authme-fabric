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

    /**
     * Parses a configured value as AuthMe does (case-insensitive).
     *
     * <p>Configuration errors must not silently select a weaker password algorithm, so missing
     * values are handled by the configuration layer and invalid values fail closed here.</p>
     */
    public static HashAlgorithm parse(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Password hash algorithm must not be blank");
        }
        try {
            return HashAlgorithm.valueOf(value.trim().toUpperCase(java.util.Locale.ROOT).replace('-', '_'));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown password hash algorithm '" + value
                + "'; choose a supported HashAlgorithm value", e);
        }
    }
}
