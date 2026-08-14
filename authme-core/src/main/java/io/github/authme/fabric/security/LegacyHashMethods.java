package io.github.authme.fabric.security;

import io.github.authme.fabric.security.crypts.HexSaltedMethod;
import io.github.authme.fabric.security.crypts.SeparateSaltMethod;
import io.github.authme.fabric.security.crypts.UnsaltedMethod;
import io.github.authme.fabric.totp.TotpProvider;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Compatibility implementations for the legacy AuthMe hash formats.
 *
 * <p>These formats are intentionally kept for migration and verification of existing accounts.
 * New installations should use Argon2id, BCrypt or PBKDF2. The implementations are self-contained
 * so importing a database does not silently turn an accepted AuthMe configuration into a no-op.</p>
 */
public final class LegacyHashMethods {

    private static final SecureRandom RANDOM = new SecureRandom();

    private LegacyHashMethods() {
    }

    public static EncryptionMethod cmw() { return new Cmw(); }
    public static EncryptionMethod crazyCrypt1() { return new CrazyCrypt1(); }
    public static EncryptionMethod doubleMd5() { return new DoubleMd5(); }
    public static EncryptionMethod ipb3() { return new Ipb3(); }
    public static EncryptionMethod ipb4() { return new Ipb4(); }
    public static EncryptionMethod joomla() { return new Joomla(); }
    public static EncryptionMethod md5vb() { return new Md5vb(); }
    public static EncryptionMethod mybb() { return new Mybb(); }
    public static EncryptionMethod pbkdf2Django() { return new Pbkdf2Django(); }
    public static EncryptionMethod phpbb() { return new Phpbb(); }
    public static EncryptionMethod phpFusion() { return new PhpFusion(); }
    public static EncryptionMethod royalAuth() { return new RoyalAuth(); }
    public static EncryptionMethod smf() { return new Smf(); }
    public static EncryptionMethod twoFactor() { return new TwoFactor(); }
    public static EncryptionMethod wbb3() { return new Wbb3(); }
    public static EncryptionMethod wbb4() { return new Wbb4(); }
    public static EncryptionMethod wordpress() { return new Wordpress(); }
    public static EncryptionMethod xfBcrypt() { return new XfBcrypt(); }

    private static final class Cmw extends UnsaltedMethod {
        @Override public String computeHash(String password) {
            return HashUtils.md5(HashUtils.sha1(password));
        }
    }

    private static final class DoubleMd5 extends UnsaltedMethod {
        @Override public String computeHash(String password) {
            return HashUtils.md5(HashUtils.md5(password));
        }
    }

    private static final class CrazyCrypt1 implements EncryptionMethod {
        @Override public HashedPassword computeHash(String password, String name) {
            String text = "ÜÄaeut//&/=I " + password + "7421€547" + name + "__+IÄIH§%NK " + password;
            byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-512");
                md.update(bytes, 0, Math.min(text.length(), bytes.length));
                return new HashedPassword(hex(md.digest()));
            } catch (Exception e) {
                throw new IllegalStateException("SHA-512 is unavailable", e);
            }
        }

        @Override public String computeHash(String password, String salt, String name) {
            return computeHash(password, name).getHash();
        }

        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            return stored != null && HashUtils.isEqual(stored.getHash(), computeHash(password, name).getHash());
        }

        @Override public String generateSalt() { return ""; }
        @Override public boolean hasSeparateSalt() { return false; }
    }

    private static final class Ipb3 extends SeparateSaltMethod {
        @Override public String computeHash(String password, String salt, String name) {
            return HashUtils.md5(HashUtils.md5(salt) + HashUtils.md5(password));
        }
        @Override public String generateSalt() { return RandomStringUtils.generateHex(5); }
    }

    private static final class Ipb4 implements EncryptionMethod {
        private static final int COST = 13;

        @Override public HashedPassword computeHash(String password, String name) {
            byte[] salt = randomBytes(16);
            String hash = OpenBSDBCrypt.generate("2a", password.toCharArray(), salt, COST);
            return new HashedPassword(hash, hash.substring(7, 29));
        }

        @Override public String computeHash(String password, String salt, String name) {
            return OpenBSDBCrypt.generate("2a", password.toCharArray(), decodeBcryptSalt(salt), COST);
        }

        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            return stored != null && HashUtils.isValidBcryptHash(stored.getHash())
                && OpenBSDBCrypt.checkPassword(stored.getHash(), password.toCharArray());
        }

        @Override public String generateSalt() { return RandomStringUtils.generateLowerUpper(22); }
        @Override public boolean hasSeparateSalt() { return true; }
    }

    private static final class Joomla extends HexSaltedMethod {
        @Override public String computeHash(String password, String salt, String name) {
            return HashUtils.md5(password + salt) + ":" + salt;
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            String[] parts = stored.getHash().split(":", -1);
            return parts.length == 2 && HashUtils.isEqual(stored.getHash(), computeHash(password, parts[1], name));
        }
        @Override public int getSaltLength() { return 32; }
    }

    private static final class Md5vb extends HexSaltedMethod {
        @Override public String computeHash(String password, String salt, String name) {
            return "$MD5vb$" + salt + "$" + HashUtils.md5(HashUtils.md5(password) + salt);
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            String[] parts = stored.getHash().split("\\$", -1);
            return parts.length == 4 && HashUtils.isEqual(stored.getHash(), computeHash(password, parts[2], name));
        }
        @Override public int getSaltLength() { return 16; }
    }

    private static final class Mybb extends SeparateSaltMethod {
        @Override public String computeHash(String password, String salt, String name) {
            return HashUtils.md5(HashUtils.md5(salt) + HashUtils.md5(password));
        }
        @Override public String generateSalt() { return RandomStringUtils.generateLowerUpper(8); }
    }

    private static final class Pbkdf2Django extends HexSaltedMethod {
        private static final int ITERATIONS = 24_000;

        @Override public String computeHash(String password, String salt, String name) {
            byte[] derived = derive(password, salt, ITERATIONS);
            return "pbkdf2_sha256$" + ITERATIONS + "$" + salt + "$"
                + Base64.getEncoder().encodeToString(derived);
        }

        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            String[] parts = stored.getHash().split("\\$", -1);
            if (parts.length != 4 || !"pbkdf2_sha256".equals(parts[0])) return false;
            try {
                int rounds = Integer.parseInt(parts[1]);
                byte[] expected = Base64.getDecoder().decode(parts[3]);
                return MessageDigest.isEqual(expected, derive(password, parts[2], rounds));
            } catch (RuntimeException e) {
                return false;
            }
        }

        @Override public int getSaltLength() { return 12; }

        private static byte[] derive(String password, String salt, int rounds) {
            if (rounds < 1 || rounds > 10_000_000) throw new IllegalArgumentException("Invalid PBKDF2 rounds");
            PKCS5S2ParametersGenerator generator = new PKCS5S2ParametersGenerator(new SHA256Digest());
            generator.init(password.getBytes(StandardCharsets.US_ASCII), salt.getBytes(StandardCharsets.US_ASCII), rounds);
            return ((KeyParameter) generator.generateDerivedMacParameters(256)).getKey();
        }
    }

    private static final class Phpbb implements EncryptionMethod {
        private final FixedBcrypt bcrypt = new FixedBcrypt("2y", 10);

        @Override public HashedPassword computeHash(String password, String name) { return bcrypt.computeHash(password, name); }
        @Override public String computeHash(String password, String salt, String name) { return bcrypt.computeHash(password, salt, name); }

        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            String hash = stored.getHash();
            if (HashUtils.isValidBcryptHash(hash)) {
                return OpenBSDBCrypt.checkPassword(hash, password.toCharArray());
            }
            if (hash.length() == 34 && hash.startsWith("$H$")) {
                return HashUtils.isEqual(hash, phpass(password, hash));
            }
            return HashUtils.isEqual(hash, HashUtils.md5(password));
        }

        @Override public String generateSalt() { return RandomStringUtils.generateLowerUpper(22); }
        @Override public boolean hasSeparateSalt() { return false; }
    }

    private static final class PhpFusion extends SeparateSaltMethod {
        @Override public String computeHash(String password, String salt, String name) {
            try {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(HashUtils.sha1(salt).getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
                return hex(mac.doFinal(password.getBytes(StandardCharsets.US_ASCII)));
            } catch (Exception e) {
                throw new IllegalStateException("Cannot create PHPFusion hash", e);
            }
        }
        @Override public String generateSalt() { return RandomStringUtils.generateHex(12); }
    }

    private static final class RoyalAuth extends UnsaltedMethod {
        @Override public String computeHash(String password) {
            for (int i = 0; i < 25; i++) password = HashUtils.sha512(password);
            return password;
        }
    }

    private static final class Smf implements EncryptionMethod {
        @Override public HashedPassword computeHash(String password, String name) {
            return new HashedPassword(HashUtils.sha1(name.toLowerCase(Locale.ROOT) + password), generateSalt());
        }
        @Override public String computeHash(String password, String salt, String name) {
            return HashUtils.sha1(name.toLowerCase(Locale.ROOT) + password);
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            return stored != null && HashUtils.isEqual(stored.getHash(), computeHash(password, null, name));
        }
        @Override public String generateSalt() { return RandomStringUtils.generate(4); }
        @Override public boolean hasSeparateSalt() { return true; }
    }

    private static final class TwoFactor extends UnsaltedMethod {
        @Override public String computeHash(String password) {
            return TotpProvider.base32Encode(randomBytes(10));
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null || password == null) return false;
            final int entered;
            try {
                if (password.trim().length() != 6) return false;
                entered = Integer.parseInt(password.trim());
            } catch (NumberFormatException e) {
                return false;
            }
            try {
                byte[] key = TotpProvider.base32Decode(stored.getHash());
                long counter = System.currentTimeMillis() / 1000L / 30L;
                for (int offset = -3; offset <= 3; offset++) {
                    if (totpCode(key, counter + offset) == entered) return true;
                }
            } catch (RuntimeException e) {
                return false;
            }
            return false;
        }
    }

    private static final class XfBcrypt extends FixedBcrypt {
        private static final Pattern HASH_PATTERN = Pattern.compile("\\\"hash\\\";s:\\d+:\\\"([^\\\"]+)\\\"");

        private XfBcrypt() {
            super("2a", 10);
        }

        @Override
        public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            String hash = extract(stored.getHash());
            return HashUtils.isValidBcryptHash(hash)
                && OpenBSDBCrypt.checkPassword(hash, password.toCharArray());
        }

        private static String extract(String value) {
            if (HashUtils.isValidBcryptHash(value)) return value;
            Matcher matcher = HASH_PATTERN.matcher(value);
            return matcher.find() ? matcher.group(1) : null;
        }
    }

    private static final class Wbb3 extends SeparateSaltMethod {
        @Override public String computeHash(String password, String salt, String name) {
            return HashUtils.sha1(salt + HashUtils.sha1(salt + HashUtils.sha1(password)));
        }
        @Override public String generateSalt() { return RandomStringUtils.generateHex(40); }
    }

    private static final class Wbb4 implements EncryptionMethod {
        private static final int COST = 8;
        @Override public HashedPassword computeHash(String password, String name) {
            byte[] salt = randomBytes(16);
            String first = OpenBSDBCrypt.generate("2a", password.toCharArray(), salt, COST);
            return new HashedPassword(OpenBSDBCrypt.generate("2a", first.toCharArray(), salt, COST));
        }
        @Override public String computeHash(String password, String salt, String name) {
            byte[] raw = decodeBcryptSalt(salt);
            String first = OpenBSDBCrypt.generate("2a", password.toCharArray(), raw, COST);
            return OpenBSDBCrypt.generate("2a", first.toCharArray(), raw, COST);
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null || stored.getHash().length() < 29) return false;
            try {
                String hash = stored.getHash();
                byte[] raw = decodeBcryptSalt(hash.substring(7, 29));
                String first = OpenBSDBCrypt.generate("2a", password.toCharArray(), raw, COST);
                return HashUtils.isEqual(hash, OpenBSDBCrypt.generate("2a", first.toCharArray(), raw, COST));
            } catch (RuntimeException e) {
                return false;
            }
        }
        @Override public String generateSalt() { return RandomStringUtils.generateLowerUpper(22); }
        @Override public boolean hasSeparateSalt() { return false; }
    }

    private static class FixedBcrypt implements EncryptionMethod {
        private final String version;
        private final int cost;
        private FixedBcrypt(String version, int cost) { this.version = version; this.cost = cost; }
        @Override public HashedPassword computeHash(String password, String name) {
            return new HashedPassword(OpenBSDBCrypt.generate(version, password.toCharArray(), randomBytes(16), cost));
        }
        @Override public String computeHash(String password, String salt, String name) {
            return OpenBSDBCrypt.generate(version, password.toCharArray(), randomBytes(16), cost);
        }
        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            return stored != null && HashUtils.isValidBcryptHash(stored.getHash())
                && OpenBSDBCrypt.checkPassword(stored.getHash(), password.toCharArray());
        }
        @Override public String generateSalt() { return RandomStringUtils.generateLowerUpper(22); }
        @Override public boolean hasSeparateSalt() { return false; }
    }

    private static final class Wordpress extends UnsaltedMethod {
        private static final String ITOA64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

        @Override public String computeHash(String password) {
            byte[] random = randomBytes(6);
            return crypt(password, "$P$" + ITOA64.charAt(13) + encode64(random, 6));
        }

        @Override public boolean comparePassword(String password, HashedPassword stored, String name) {
            if (stored == null || stored.getHash() == null) return false;
            return HashUtils.isEqual(stored.getHash(), crypt(password, stored.getHash()));
        }

        private static String crypt(String password, String setting) {
            String fallback = setting.startsWith("$0") ? "*1" : "*0";
            if (setting.length() < 12 || !(setting.startsWith("$P$") || setting.startsWith("$H$"))) return fallback;
            int log2 = ITOA64.indexOf(setting.charAt(3));
            if (log2 < 7 || log2 > 30) return fallback;
            String salt = setting.substring(4, 12);
            byte[] pass = password.getBytes(StandardCharsets.UTF_8);
            try {
                MessageDigest md = MessageDigest.getInstance("MD5");
                byte[] hash = md.digest((salt + password).getBytes(StandardCharsets.UTF_8));
                int count = 1 << log2;
                do {
                    byte[] input = new byte[hash.length + pass.length];
                    System.arraycopy(hash, 0, input, 0, hash.length);
                    System.arraycopy(pass, 0, input, hash.length, pass.length);
                    hash = md.digest(input);
                } while (--count > 0);
                return setting.substring(0, 12) + encode64(hash, 16);
            } catch (Exception e) {
                return fallback;
            }
        }
    }

    private static String phpass(String password, String setting) {
        final String alphabet = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        if (!setting.startsWith("$H$") || setting.length() < 12) return "*";
        int log2 = alphabet.indexOf(setting.charAt(3));
        if (log2 < 7 || log2 > 30) return "*";
        String salt = setting.substring(4, 12);
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest((salt + password).getBytes(StandardCharsets.ISO_8859_1));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) hex.append(String.format("%02x", b & 0xff));
            byte[] packed = packHex(hex.toString());
            int count = 1 << log2;
            do {
                byte[] input = new byte[packed.length + password.length()];
                System.arraycopy(packed, 0, input, 0, packed.length);
                System.arraycopy(password.getBytes(StandardCharsets.ISO_8859_1), 0, input, packed.length, password.length());
                byte[] next = md.digest(input);
                StringBuilder nextHex = new StringBuilder();
                for (byte b : next) nextHex.append(String.format("%02x", b & 0xff));
                packed = packHex(nextHex.toString());
            } while (--count > 0);
            return setting.substring(0, 12) + encode64(new String(packed, StandardCharsets.ISO_8859_1).getBytes(StandardCharsets.ISO_8859_1), 16);
        } catch (Exception e) {
            return "*";
        }
    }

    private static byte[] packHex(String value) {
        byte[] result = new byte[value.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static String encode64(byte[] source, int count) {
        StringBuilder out = new StringBuilder();
        int i = 0;
        while (i < count) {
            int value = source[i++] & 0xff;
            out.append(Wordpress.ITOA64.charAt(value & 0x3f));
            if (i < count) value |= (source[i] & 0xff) << 8;
            out.append(Wordpress.ITOA64.charAt((value >> 6) & 0x3f));
            if (i++ >= count) break;
            if (i < count) value |= (source[i] & 0xff) << 16;
            out.append(Wordpress.ITOA64.charAt((value >> 12) & 0x3f));
            if (i++ >= count) break;
            out.append(Wordpress.ITOA64.charAt((value >> 18) & 0x3f));
        }
        return out.toString();
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static int totpCode(byte[] key, long counter) {
        byte[] data = new byte[8];
        for (int i = 7; i >= 0; i--) {
            data[i] = (byte) counter;
            counter >>>= 8;
        }
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(key, "HmacSHA1"));
            byte[] hash = mac.doFinal(data);
            int offset = hash[hash.length - 1] & 0x0f;
            int truncated = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
            return truncated % 1_000_000;
        } catch (Exception e) {
            throw new IllegalStateException("HmacSHA1 is unavailable", e);
        }
    }

    private static byte[] decodeBcryptSalt(String encoded) {
        if (encoded == null || encoded.length() != 22) throw new IllegalArgumentException("Invalid BCrypt salt");
        String alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        byte[] out = new byte[16];
        int output = 0;
        for (int i = 0; i + 1 < encoded.length() && output < out.length;) {
            int a = alphabet.indexOf(encoded.charAt(i++));
            int b = alphabet.indexOf(encoded.charAt(i++));
            if (a < 0 || b < 0) throw new IllegalArgumentException("Invalid BCrypt salt character");
            out[output++] = (byte) ((a << 2) | (b >> 4));
            if (output >= out.length || i >= encoded.length()) break;
            int c = alphabet.indexOf(encoded.charAt(i++));
            if (c < 0) throw new IllegalArgumentException("Invalid BCrypt salt character");
            out[output++] = (byte) (((b & 0x0f) << 4) | (c >> 2));
            if (output >= out.length || i >= encoded.length()) break;
            int d = alphabet.indexOf(encoded.charAt(i++));
            if (d < 0) throw new IllegalArgumentException("Invalid BCrypt salt character");
            out[output++] = (byte) (((c & 0x03) << 6) | d);
        }
        return out;
    }

    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) out.append(String.format("%02x", b & 0xff));
        return out.toString();
    }
}
