package io.github.authme.fabric.security.crypts;

import io.github.authme.fabric.security.HashedPassword;
import org.bouncycastle.util.encoders.Hex;

/**
 * PBKDF2-HmacSHA256 with a hex-encoded salt embedded in the hash, mirroring AuthMe's {@code Pbkdf2}.
 *
 * <p>Format: {@code pbkdf2_sha256$<iterations>$<16-hex-salt>$<uppercase-hex(64-byte-derived-key)>}.
 * The salt passed to the derivation is the raw UTF-8 bytes of the 16-char hex string (matching AuthMe).
 */
public class Pbkdf2 extends AbstractPbkdf2 {

    private static final int DEFAULT_ROUNDS = 10_000;

    public Pbkdf2() {
        this(DEFAULT_ROUNDS);
    }

    public Pbkdf2(int rounds) {
        super(rounds);
    }

    @Override
    public String computeHash(String password, String salt, String name) {
        return "pbkdf2_sha256$" + numberOfRounds + "$" + salt + "$"
            + Hex.toHexString(deriveKey(password, salt.getBytes(), numberOfRounds, 64)).toUpperCase();
    }

    @Override
    public boolean comparePassword(String password, HashedPassword hashedPassword, String name) {
        String[] line = hashedPassword.getHash().split("\\$");
        if (line.length != 4) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(line[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        return verifyKey(password, line[2].getBytes(), iterations, Hex.decode(line[3]));
    }

    @Override
    public int getSaltLength() {
        return 16;
    }
}