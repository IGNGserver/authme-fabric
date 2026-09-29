package io.github.authme.fabric.auth;

import java.util.Locale;

/**
 * Security policy for persisted login sessions.
 *
 * <p>A session is a password bypass, so both its lifetime and its originating
 * address are mandatory. Keeping this policy in the shared core prevents the
 * three Minecraft-version modules from drifting apart.</p>
 */
public final class SessionSecurityPolicy {

    private SessionSecurityPolicy() {
    }

    public static boolean canResume(String storedIp, String currentIp, long lastLogin,
                                    long now, long timeoutMillis) {
        if (storedIp == null || currentIp == null || storedIp.isBlank() || currentIp.isBlank()
            || lastLogin <= 0L || timeoutMillis <= 0L || now < lastLogin) return false;
        long elapsed = now - lastLogin;
        return elapsed <= timeoutMillis && normalize(storedIp).equals(normalize(currentIp));
    }

    private static String normalize(String address) {
        String value = address.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("[") && value.contains("]")) {
            value = value.substring(1, value.indexOf(']'));
        }
        return value;
    }
}
