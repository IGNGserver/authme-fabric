package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;

import java.util.UUID;

/**
 * An account record as stored in the AuthMe database. Field names and semantics mirror AuthMe's
 * {@code fr.xephi.authme.data.auth.PlayerAuth} so records read from a shared database are interpreted
 * identically by this port and the original plugin.
 */
public final class PlayerAuth {

    private int id;
    private String name;        // stored lower-case in the `username` column
    private String realName;    // original-case display name (`realname` column)
    private String hash;        // password hash column
    private String salt;        // salt column (may be null if algorithm embeds salt)
    private String lastIp;
    private String email;
    private Long lastLogin;     // epoch millis, may be null
    private long registrationDate;
    private String registrationIp;
    private double locX, locY, locZ;
    private String locWorld;
    private float locYaw, locPitch;
    private boolean logged;
    private boolean hasSession;
    private String totpKey;
    private UUID uuid;
    private UUID premiumUuid;
    private int groupId = -1;

    private PlayerAuth() {
    }

    public static Builder builder() {
        return new Builder();
    }

    public int getId() { return id; }
    public String getName() { return name; }
    public String getRealName() { return realName; }
    public String getHash() { return hash; }
    public String getSalt() { return salt; }
    public String getLastIp() { return lastIp; }
    public String getEmail() { return email; }
    public Long getLastLogin() { return lastLogin; }
    public long getRegistrationDate() { return registrationDate; }
    public String getRegistrationIp() { return registrationIp; }
    public double getLocX() { return locX; }
    public double getLocY() { return locY; }
    public double getLocZ() { return locZ; }
    public String getLocWorld() { return locWorld; }
    public float getLocYaw() { return locYaw; }
    public float getLocPitch() { return locPitch; }
    public boolean isLogged() { return logged; }
    public boolean hasSession() { return hasSession; }
    public String getTotpKey() { return totpKey; }
    public UUID getUuid() { return uuid; }
    public UUID getPremiumUuid() { return premiumUuid; }
    public int getGroupId() { return groupId; }

    public HashedPassword toHashedPassword() {
        return new HashedPassword(hash, salt != null && !salt.isEmpty() ? salt : null);
    }

    public void setHash(String hash) { this.hash = hash; }
    public void setSalt(String salt) { this.salt = salt; }
    public void setRealName(String realName) { this.realName = realName; }
    public void setLastIp(String lastIp) { this.lastIp = lastIp; }
    public void setEmail(String email) { this.email = email; }
    public void setLastLogin(Long lastLogin) { this.lastLogin = lastLogin; }
    public void setLogged(boolean logged) { this.logged = logged; }
    public void setHasSession(boolean hasSession) { this.hasSession = hasSession; }
    public void setLocWorld(String world) { this.locWorld = world; }
    public void setLocX(double v) { this.locX = v; }
    public void setLocY(double v) { this.locY = v; }
    public void setLocZ(double v) { this.locZ = v; }
    public void setLocYaw(float v) { this.locYaw = v; }
    public void setLocPitch(float v) { this.locPitch = v; }
    public void setTotpKey(String key) { this.totpKey = key; }
    public void setPremiumUuid(UUID u) { this.premiumUuid = u; }
    public void setUuid(UUID u) { this.uuid = u; }

    public static final class Builder {
        private final PlayerAuth a = new PlayerAuth();

        public Builder name(String v) { a.name = v; return this; }
        public Builder realName(String v) { a.realName = v; return this; }
        public Builder password(String hash, String salt) { a.hash = hash; a.salt = salt; return this; }
        public Builder lastIp(String v) { a.lastIp = v; return this; }
        public Builder email(String v) { a.email = v; return this; }
        public Builder lastLogin(Long v) { a.lastLogin = v; return this; }
        public Builder registrationDate(long v) { a.registrationDate = v; return this; }
        public Builder registrationIp(String v) { a.registrationIp = v; return this; }
        public Builder locWorld(String v) { a.locWorld = v; return this; }
        public Builder locX(double v) { a.locX = v; return this; }
        public Builder locY(double v) { a.locY = v; return this; }
        public Builder locZ(double v) { a.locZ = v; return this; }
        public Builder locYaw(float v) { a.locYaw = v; return this; }
        public Builder locPitch(float v) { a.locPitch = v; return this; }
        public Builder logged(boolean v) { a.logged = v; return this; }
        public Builder hasSession(boolean v) { a.hasSession = v; return this; }
        public Builder totpKey(String v) { a.totpKey = v; return this; }
        public Builder uuid(UUID v) { a.uuid = v; return this; }
        public Builder premiumUuid(UUID v) { a.premiumUuid = v; return this; }
        public Builder groupId(int v) { a.groupId = v; return this; }
        public Builder id(int v) { a.id = v; return this; }

        public PlayerAuth build() { return a; }
    }
}
