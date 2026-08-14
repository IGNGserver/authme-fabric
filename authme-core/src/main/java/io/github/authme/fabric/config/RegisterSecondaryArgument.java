package io.github.authme.fabric.config;

/**
 * Meaning of the optional second argument to {@code /register}.
 * Values mirror AuthMeReloaded's {@code RegisterSecondaryArgument} enum.
 */
public enum RegisterSecondaryArgument {
    NONE,
    CONFIRMATION,
    EMAIL_MANDATORY,
    EMAIL_OPTIONAL;

    public static RegisterSecondaryArgument parse(Object value,
                                                    RegisterSecondaryArgument fallback) {
        if (value == null) return fallback;
        try {
            return valueOf(String.valueOf(value).trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }
}
