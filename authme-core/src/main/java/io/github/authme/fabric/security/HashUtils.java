package io.github.authme.fabric.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hashing utilities mirroring AuthMe's {@code fr.xephi.authme.security.HashUtils} so that hashes are
 * byte-for-byte identical to those produced by the original plugin.
 */
public final class HashUtils {

    private HashUtils() {
    }

    public static String sha1(String message) {
        return hash(message, "SHA-1");
    }

    public static String sha256(String message) {
        return hash(message, "SHA-256");
    }

    public static String sha512(String message) {
        return hash(message, "SHA-512");
    }

    public static String md5(String message) {
        return hash(message, "MD5");
    }

    public static boolean isEqual(String string1, String string2) {
        return MessageDigest.isEqual(
            string1.getBytes(StandardCharsets.UTF_8),
            string2.getBytes(StandardCharsets.UTF_8));
    }

    public static boolean isValidBcryptHash(String hash) {
        return hash.length() == 60 && hash.substring(0, 2).equals("$2");
    }

    public static String hmacSha256(String secret, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] digest = mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
            return String.format("%064x", new BigInteger(1, digest));
        } catch (NoSuchAlgorithmException | java.security.InvalidKeyException e) {
            throw new UnsupportedOperationException("HmacSHA256 is not available on this system", e);
        }
    }

    public static String hash(String message, MessageDigest algorithm) {
        algorithm.reset();
        algorithm.update(message.getBytes());
        byte[] digest = algorithm.digest();
        return String.format("%0" + (digest.length << 1) + "x", new BigInteger(1, digest));
    }

    private static String hash(String message, String algorithm) {
        try {
            return hash(message, MessageDigest.getInstance(algorithm));
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException("Your system seems not to support the hash algorithm '" + algorithm + "'", e);
        }
    }
}