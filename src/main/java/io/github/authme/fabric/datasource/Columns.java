package io.github.authme.fabric.datasource;

/**
 * Configurable database column names. Mirrors AuthMe's {@code fr.xephi.authme.datasource.Columns}.
 * Defaults correspond to the AuthMe default config.yml so a table created by the original plugin can
 * be used unchanged.
 */
public final class Columns {

    public final String NAME;
    public final String REAL_NAME;
    public final String PASSWORD;
    public final String SALT;
    public final String TOTP_KEY;
    public final String LAST_IP;
    public final String LAST_LOGIN;
    public final String GROUP;
    public final String LASTLOC_X;
    public final String LASTLOC_Y;
    public final String LASTLOC_Z;
    public final String LASTLOC_WORLD;
    public final String LASTLOC_YAW;
    public final String LASTLOC_PITCH;
    public final String EMAIL;
    public final String ID;
    public final String IS_LOGGED;
    public final String HAS_SESSION;
    public final String REGISTRATION_DATE;
    public final String REGISTRATION_IP;
    public final String PLAYER_UUID;
    public final String PREMIUM_UUID;

    public Columns(Builder b) {
        this.NAME = b.name;
        this.REAL_NAME = b.realName;
        this.PASSWORD = b.password;
        this.SALT = b.salt;
        this.TOTP_KEY = b.totpKey;
        this.LAST_IP = b.lastIp;
        this.LAST_LOGIN = b.lastLogin;
        this.GROUP = b.group;
        this.LASTLOC_X = b.lastlocX;
        this.LASTLOC_Y = b.lastlocY;
        this.LASTLOC_Z = b.lastlocZ;
        this.LASTLOC_WORLD = b.lastlocWorld;
        this.LASTLOC_YAW = b.lastlocYaw;
        this.LASTLOC_PITCH = b.lastlocPitch;
        this.EMAIL = b.email;
        this.ID = b.id;
        this.IS_LOGGED = b.isLogged;
        this.HAS_SESSION = b.hasSession;
        this.REGISTRATION_DATE = b.regDate;
        this.REGISTRATION_IP = b.regIp;
        this.PLAYER_UUID = b.playerUuid;
        this.PREMIUM_UUID = b.premiumUuid;
    }

    public boolean hasSaltColumn() {
        return SALT != null && !SALT.isEmpty();
    }

    public boolean hasPlayerUuidColumn() {
        return PLAYER_UUID != null && !PLAYER_UUID.isEmpty();
    }

    public boolean hasPremiumUuidColumn() {
        return PREMIUM_UUID != null && !PREMIUM_UUID.isEmpty();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String name = "username";
        private String realName = "realname";
        private String password = "password";
        private String salt = "";
        private String totpKey = "totp";
        private String lastIp = "ip";
        private String lastLogin = "lastlogin";
        private String group = "";
        private String lastlocX = "x";
        private String lastlocY = "y";
        private String lastlocZ = "z";
        private String lastlocWorld = "world";
        private String lastlocYaw = "yaw";
        private String lastlocPitch = "pitch";
        private String email = "email";
        private String id = "id";
        private String isLogged = "isLogged";
        private String hasSession = "hasSession";
        private String regDate = "regdate";
        private String regIp = "regip";
        private String playerUuid = "";
        private String premiumUuid = "premiumUUID";

        public Builder name(String v) { this.name = v; return this; }
        public Builder realName(String v) { this.realName = v; return this; }
        public Builder password(String v) { this.password = v; return this; }
        public Builder salt(String v) { this.salt = v; return this; }
        public Builder totpKey(String v) { this.totpKey = v; return this; }
        public Builder lastIp(String v) { this.lastIp = v; return this; }
        public Builder lastLogin(String v) { this.lastLogin = v; return this; }
        public Builder group(String v) { this.group = v; return this; }
        public Builder lastlocX(String v) { this.lastlocX = v; return this; }
        public Builder lastlocY(String v) { this.lastlocY = v; return this; }
        public Builder lastlocZ(String v) { this.lastlocZ = v; return this; }
        public Builder lastlocWorld(String v) { this.lastlocWorld = v; return this; }
        public Builder lastlocYaw(String v) { this.lastlocYaw = v; return this; }
        public Builder lastlocPitch(String v) { this.lastlocPitch = v; return this; }
        public Builder email(String v) { this.email = v; return this; }
        public Builder id(String v) { this.id = v; return this; }
        public Builder isLogged(String v) { this.isLogged = v; return this; }
        public Builder hasSession(String v) { this.hasSession = v; return this; }
        public Builder regDate(String v) { this.regDate = v; return this; }
        public Builder regIp(String v) { this.regIp = v; return this; }
        public Builder playerUuid(String v) { this.playerUuid = v; return this; }
        public Builder premiumUuid(String v) { this.premiumUuid = v; return this; }
        public Columns build() { return new Columns(this); }
    }
}