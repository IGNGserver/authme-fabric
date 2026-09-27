package io.github.authme.fabric.auth;

import java.util.List;
import java.util.Locale;

/** Normalizes AuthMe's command allow-list entries and compares command roots safely. */
public final class CommandTokenPolicy {

    private CommandTokenPolicy() {
    }

    public static boolean isAllowed(String rootToken, List<String> allowedCommands) {
        String requested = normalize(rootToken);
        if (requested.isEmpty() || allowedCommands == null) return false;
        for (String configured : allowedCommands) {
            if (requested.equals(normalize(configured))) return true;
        }
        return false;
    }

    public static String normalize(String value) {
        if (value == null) return "";
        String token = value.trim().toLowerCase(Locale.ROOT);
        while (token.startsWith("/")) token = token.substring(1).trim();
        for (int i = 0; i < token.length(); i++) {
            if (Character.isWhitespace(token.charAt(i))) {
                return token.substring(0, i);
            }
        }
        return token;
    }
}
