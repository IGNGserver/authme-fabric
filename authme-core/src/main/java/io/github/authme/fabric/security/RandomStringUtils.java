package io.github.authme.fabric.security;

import java.security.SecureRandom;
import java.util.Random;

/**
 * Mirrors AuthMe's {@code fr.xephi.authme.util.RandomStringUtils}, used to generate salts so they are
 * identical to those produced by the original plugin.
 */
public final class RandomStringUtils {

    private static final char[] CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray();
    private static final Random RANDOM = new SecureRandom();
    private static final int NUM_INDEX = 10;
    private static final int LOWER_ALPHANUMERIC_INDEX = 36;
    private static final int HEX_MAX_INDEX = 16;

    private RandomStringUtils() {
    }

    public static String generate(int length) {
        return generateString(length, LOWER_ALPHANUMERIC_INDEX);
    }

    public static String generateHex(int length) {
        return generateString(length, HEX_MAX_INDEX);
    }

    public static String generateNum(int length) {
        return generateString(length, NUM_INDEX);
    }

    public static String generateLowerUpper(int length) {
        return generateString(length, CHARS.length);
    }

    private static String generateString(int length, int maxIndex) {
        if (length < 0) {
            throw new IllegalArgumentException("Length must be positive but was " + length);
        }
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; ++i) {
            sb.append(CHARS[RANDOM.nextInt(maxIndex)]);
        }
        return sb.toString();
    }
}