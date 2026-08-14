package io.github.authme.fabric.config;

/**
 * AuthMe registration mode.  The names intentionally match AuthMeReloaded's
 * {@code settings.registration.type} enum so an existing configuration can be
 * copied without translation.
 */
public enum RegistrationType {
    PASSWORD,
    EMAIL;

    public static RegistrationType parse(Object value, RegistrationType fallback) {
        if (value == null) return fallback;
        try {
            return valueOf(String.valueOf(value).trim().toUpperCase(java.util.Locale.ROOT));
        } catch (IllegalArgumentException ignored) {
            return fallback;
        }
    }
}
