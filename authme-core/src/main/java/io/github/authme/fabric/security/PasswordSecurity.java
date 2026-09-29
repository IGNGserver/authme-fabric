package io.github.authme.fabric.security;

import io.github.authme.fabric.security.crypts.Argon2;
import io.github.authme.fabric.security.crypts.Argon2Id;
import io.github.authme.fabric.security.crypts.BCrypt;
import io.github.authme.fabric.security.crypts.DoubleSha512;
import io.github.authme.fabric.security.crypts.Md5;
import io.github.authme.fabric.security.crypts.Pbkdf2;
import io.github.authme.fabric.security.crypts.Pbkdf2Base64;
import io.github.authme.fabric.security.crypts.Plain;
import io.github.authme.fabric.security.crypts.Salted2Md5;
import io.github.authme.fabric.security.crypts.SaltedSha256;
import io.github.authme.fabric.security.crypts.SaltedSha512;
import io.github.authme.fabric.security.crypts.Sha1;
import io.github.authme.fabric.security.crypts.Sha256;
import io.github.authme.fabric.security.crypts.Sha512;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Builds the configured {@link EncryptionMethod} and verifies passwords, including fallback to
 * legacy hash algorithms (so accounts can be migrated from one algorithm to another, like AuthMe).
 */
public final class PasswordSecurity {

    private static final int MAX_PASSWORD_INPUT_LENGTH = 256;
    private static final int MAX_STORED_HASH_LENGTH = 4096;
    private static final int MAX_STORED_SALT_LENGTH = 1024;

    private final EncryptionMethod primaryMethod;
    private final HashAlgorithm primaryAlgorithm;
    private final List<EncryptionMethod> legacyMethods;

    public PasswordSecurity(HashAlgorithm primary, int pbkdf2Rounds, int bcryptLog2Round,
                            int doubleMd5SaltLength, List<HashAlgorithm> legacyHashes) {
        this.primaryAlgorithm = primary;
        this.primaryMethod = createMethod(primary, pbkdf2Rounds, bcryptLog2Round, doubleMd5SaltLength);
        this.legacyMethods = new ArrayList<>();
        if (legacyHashes != null) {
            for (HashAlgorithm a : legacyHashes) {
                if (a != primary) {
                    legacyMethods.add(createMethod(a, pbkdf2Rounds, bcryptLog2Round, doubleMd5SaltLength));
                }
            }
        }
    }

    public HashedPassword computeHash(String password, String name) {
        if (primaryMethod == null) {
            throw new IllegalStateException("The CUSTOM password algorithm requires an external implementation");
        }
        return primaryMethod.computeHash(password, name);
    }

    public EncryptionMethod getPrimaryMethod() {
        return primaryMethod;
    }

    public boolean hasSeparateSalt() {
        return primaryMethod != null && primaryMethod.hasSeparateSalt();
    }

    /**
     * Verifies a password against a stored hash, trying the primary algorithm first and then any
     * configured legacy algorithms.
     *
     * @return a {@link VerificationResult} describing which algorithm matched, or {@code null}
     *         if none matched.
     */
    public VerificationResult verify(String password, HashedPassword hashedPassword, String name) {
        if (password == null || hashedPassword == null || hashedPassword.getHash() == null) {
            return null;
        }
        if (password.length() > MAX_PASSWORD_INPUT_LENGTH
            || hashedPassword.getHash().length() > MAX_STORED_HASH_LENGTH
            || (hashedPassword.getSalt() != null && hashedPassword.getSalt().length() > MAX_STORED_SALT_LENGTH)) {
            return null;
        }
        if (safeCompare(primaryMethod, password, hashedPassword, name)) {
            return new VerificationResult(primaryAlgorithm, false);
        }
        for (int i = 0; i < legacyMethods.size(); i++) {
            EncryptionMethod m = legacyMethods.get(i);
            if (safeCompare(m, password, hashedPassword, name)) {
                return new VerificationResult(null, true);
            }
        }
        return null;
    }

    private static boolean safeCompare(EncryptionMethod method, String password,
                                       HashedPassword hashedPassword, String name) {
        if (method == null || (method.hasSeparateSalt() && hashedPassword.getSalt() == null)) return false;
        try {
            return method.comparePassword(password, hashedPassword, name);
        } catch (RuntimeException malformedHash) {
            return false;
        }
    }

    public boolean matches(String password, HashedPassword hashedPassword, String name) {
        return verify(password, hashedPassword, name) != null;
    }

    private static EncryptionMethod createMethod(HashAlgorithm algorithm, int pbkdf2Rounds,
                                                 int bcryptLog2Round, int doubleMd5SaltLength) {
        switch (algorithm) {
            case SHA256: return new Sha256();
            case SHA512: return new Sha512();
            case SHA1: return new Sha1();
            case MD5: return new Md5();
            case DOUBLE_SHA512: return new DoubleSha512();
            case PLAINTEXT: return new Plain();
            case SALTEDSHA256: return new SaltedSha256();
            case SALTEDSHA512: return new SaltedSha512();
            case SALTED2MD5: return new Salted2Md5(Math.max(1, doubleMd5SaltLength));
            case BCRYPT: return new BCrypt("2a", Math.max(4, Math.min(31, bcryptLog2Round)));
            case BCRYPT2Y: return new BCrypt("2y", Math.max(4, Math.min(31, bcryptLog2Round)));
            case PBKDF2: return new Pbkdf2(Math.max(1, pbkdf2Rounds));
            case PBKDF2BASE64: return new Pbkdf2Base64(Math.max(1, pbkdf2Rounds));
            case ARGON2: return new Argon2();
            case ARGON2ID: return new Argon2Id();
            case CMW: return LegacyHashMethods.cmw();
            case CRAZYCRYPT1: return LegacyHashMethods.crazyCrypt1();
            case DOUBLEMD5: return LegacyHashMethods.doubleMd5();
            case IPB3: return LegacyHashMethods.ipb3();
            case IPB4: return LegacyHashMethods.ipb4();
            case JOOMLA: return LegacyHashMethods.joomla();
            case MD5VB: return LegacyHashMethods.md5vb();
            case MYBB: return LegacyHashMethods.mybb();
            case PBKDF2DJANGO: return LegacyHashMethods.pbkdf2Django();
            case PHPBB: return LegacyHashMethods.phpbb();
            case PHPFUSION: return LegacyHashMethods.phpFusion();
            case ROYALAUTH: return LegacyHashMethods.royalAuth();
            case SMF: return LegacyHashMethods.smf();
            case TWO_FACTOR: return LegacyHashMethods.twoFactor();
            case WBB3: return LegacyHashMethods.wbb3();
            case WBB4: return LegacyHashMethods.wbb4();
            case WORDPRESS: return LegacyHashMethods.wordpress();
            case XFBCRYPT: return LegacyHashMethods.xfBcrypt();
            case CUSTOM: return null;
            default:
                throw new IllegalArgumentException("Hash algorithm '" + algorithm
                    + "' is not supported by this build.");
        }
    }

    /** Result of a password verification. */
    public static final class VerificationResult {
        private final HashAlgorithm matchedAlgorithm;
        private final boolean legacy;

        VerificationResult(HashAlgorithm matchedAlgorithm, boolean legacy) {
            this.matchedAlgorithm = matchedAlgorithm;
            this.legacy = legacy;
        }

        public boolean isLegacy() {
            return legacy;
        }

        public HashAlgorithm getMatchedAlgorithm() {
            return matchedAlgorithm;
        }
    }

    @SuppressWarnings("unused")
    private static String lower(String s) {
        return s == null ? "" : s.toLowerCase(Locale.ROOT);
    }
}
