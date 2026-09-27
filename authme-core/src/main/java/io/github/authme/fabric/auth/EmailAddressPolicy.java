package io.github.authme.fabric.auth;

/** Conservative, bounded validation for addresses accepted by AuthMe commands. */
public final class EmailAddressPolicy {

    private static final int MAX_LENGTH = 254;
    private static final int MAX_LOCAL_LENGTH = 64;
    private static final int MAX_DOMAIN_LABEL_LENGTH = 63;

    private EmailAddressPolicy() {
    }

    /**
     * Accepts ordinary ASCII mailbox addresses suitable for SMTP envelope use.
     * Quoted local parts, comments, and internationalized addresses are deliberately
     * rejected until the mail transport supports them consistently.
     */
    public static boolean isValid(String value) {
        if (value == null || value.length() < 3 || value.length() > MAX_LENGTH) return false;
        int at = value.indexOf('@');
        if (at <= 0 || at != value.lastIndexOf('@') || at > MAX_LOCAL_LENGTH) return false;
        String local = value.substring(0, at);
        String domain = value.substring(at + 1);
        if (domain.isEmpty() || domain.length() > 253 || domain.indexOf('.') <= 0
            || domain.endsWith(".")) return false;
        if (local.startsWith(".") || local.endsWith(".") || local.contains("..")) return false;
        for (int i = 0; i < local.length(); i++) {
            char c = local.charAt(i);
            if (!isLocalChar(c)) return false;
        }
        String[] labels = domain.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > MAX_DOMAIN_LABEL_LENGTH
                || label.startsWith("-") || label.endsWith("-")) return false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(isAsciiLetter(c) || isAsciiDigit(c) || c == '-')) return false;
            }
        }
        return true;
    }

    private static boolean isLocalChar(char c) {
        return isAsciiLetter(c) || isAsciiDigit(c)
            || "!#$%&'*+-/=?^_`{|}~.".indexOf(c) >= 0;
    }

    private static boolean isAsciiLetter(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
    }

    private static boolean isAsciiDigit(char c) {
        return c >= '0' && c <= '9';
    }
}
