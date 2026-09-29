package io.github.authme.fabric.totp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * RFC 6238 TOTP implementation compatible with Google Authenticator / AuthMe's googleauth-based
 * two-factor codes (HMAC-SHA1, 30-second period, 6 digits, secret stored Base32-encoded).
 */
public final class TotpProvider {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] DECODE = new int[128];
    private static final int MAX_SECRET_LENGTH = 256;

    static {
        Arrays.fill(DECODE, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            DECODE[ALPHABET[i]] = i;
            if (Character.isLowerCase(ALPHABET[i])) {
                DECODE[ALPHABET[i]] = i;
            }
        }
        // also accept lowercase
        for (char c = 'a'; c <= 'z'; c++) {
            DECODE[c] = DECODE[Character.toUpperCase(c)];
        }
    }

    private TotpProvider() {
    }

    /**
     * @param completeSecret the Base32-encoded shared secret (uppercase, no padding)
     * @return true if the secret is a syntactically valid Base32 string of >= 2 chars
     */
    public static boolean isPlausibleSecret(String completeSecret) {
        if (completeSecret == null || completeSecret.length() < 2) return false;
        String s = completeSecret.toUpperCase(Locale.ROOT).replace(" ", "");
        if (s.length() > MAX_SECRET_LENGTH) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 128 || DECODE[c] < 0) return false;
        }
        return s.length() >= 16;
    }

    /**
     * Validates a 6-digit code against {@code completeSecret} allowing a ±1 time window.
     */
    public static boolean validateCode(String completeSecret, String code) {
        if (!isPlausibleSecret(completeSecret) || code == null) return false;
        String trimmed = code.trim();
        if (trimmed.length() != 6) return false;
        int entered;
        try {
            entered = Integer.parseInt(trimmed.substring(0, 6));
        } catch (NumberFormatException e) {
            return false;
        }
        byte[] key;
        try {
            key = base32Decode(completeSecret);
        } catch (IllegalArgumentException e) {
            return false;
        }
        long currentCounter = System.currentTimeMillis() / 1000L / 30L;
        for (int offset = -1; offset <= 1; offset++) {
            if (compute(key, currentCounter + offset) == entered) {
                return true;
            }
        }
        return false;
    }

    public static String generateSecret() {
        byte[] key = new byte[20];
        new java.security.SecureRandom().nextBytes(key);
        return base32Encode(key);
    }

    private static int compute(byte[] key, long counter) {
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(counter);
        byte[] challenge = buffer.array();
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(challenge);
            int offset = hash[hash.length - 1] & 0xF;
            // truncate to 31 bits and modulo 1_000_000
            int truncated = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
            return truncated % 1_000_000;
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new UnsupportedOperationException("HmacSHA1 unavailable", e);
        }
    }

    public static byte[] base32Decode(String base32) {
        if (base32 == null) throw new IllegalArgumentException("TOTP secret is missing");
        String s = base32.toUpperCase(Locale.ROOT).replace(" ", "").replace("=", "");
        if (s.isEmpty() || s.length() > MAX_SECRET_LENGTH) {
            throw new IllegalArgumentException("TOTP secret is too large");
        }
        int outLen = s.length() * 5 / 8;
        byte[] out = new byte[outLen];
        int buffer = 0;
        int bits = 0;
        int index = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= 128 || DECODE[c] < 0) {
                throw new IllegalArgumentException("Invalid Base32 char: " + c);
            }
            buffer = (buffer << 5) | DECODE[c];
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out[index++] = (byte) ((buffer >> bits) & 0xFF);
            }
        }
        return out;
    }

    public static String base32Encode(byte[] data) {
        StringBuilder sb = new StringBuilder();
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                sb.append(ALPHABET[(buffer >> bits) & 0x1F]);
            }
        }
        if (bits > 0) {
            sb.append(ALPHABET[(buffer << (5 - bits)) & 0x1F]);
        }
        return sb.toString();
    }

    public static String otpAuthUri(String issuer, String account, String completeSecret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
            urlEncode(issuer), urlEncode(account), completeSecret, urlEncode(issuer));
    }

    private static String urlEncode(String s) {
        return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unused")
    private static byte[] sha1(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }
}
