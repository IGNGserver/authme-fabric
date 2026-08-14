package io.github.authme.fabric.auth;

/**
 * Short-lived e-mail verification/recovery state. The code is kept only in memory and is never
 * persisted to the account database or written to server logs.
 */
public final class EmailChallenge {

    public final String email;
    public final String code;
    public final long expiresAt;
    public final boolean recovery;
    public volatile boolean verified;
    public int failedAttempts;

    public EmailChallenge(String email, String code, long expiresAt, boolean recovery) {
        this.email = email;
        this.code = code;
        this.expiresAt = expiresAt;
        this.recovery = recovery;
    }
}
