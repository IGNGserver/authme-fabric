package io.github.authme.fabric.auth;

import java.util.UUID;

/**
 * In-memory per-player session state held between login events. Pure data — no platform types.
 */
public final class PlayerSession {

    public final UUID uuid;
    public final String name;
    public boolean registered;
    public boolean authenticated;
    public boolean premium;
    public boolean pendingTotp;
    public boolean captchaPending;
    public String captchaCode = "";
    public int loginAttempts;
    public long joinTime;
    public String lastIp;
    public long lastLogin;
    public String totpKey = "";
    public boolean invulnerableFrozen;
    public double frozenX, frozenY, frozenZ;
    public String frozenWorld;

    public PlayerSession(UUID uuid, String name) {
        this.uuid = uuid;
        this.name = name;
    }

    public boolean isUnauthenticated() {
        return !authenticated;
    }

    public boolean needsTotp() {
        return pendingTotp;
    }
}