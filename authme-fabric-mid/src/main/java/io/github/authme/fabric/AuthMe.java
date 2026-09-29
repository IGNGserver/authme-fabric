package io.github.authme.fabric;

import io.github.authme.fabric.auth.AuthManager;
import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.GeoIpPolicy;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.MariaDBDataSource;
import io.github.authme.fabric.datasource.MySQLDataSource;
import io.github.authme.fabric.datasource.PostgreSqlDataSource;
import io.github.authme.fabric.datasource.SQLiteDataSource;
import io.github.authme.fabric.datasource.CachingDataSource;
import io.github.authme.fabric.security.PasswordSecurity;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.ProxyMessageSink;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

import java.nio.file.Path;
import java.nio.file.Files;
import java.sql.SQLException;

/**
 * Central service holder for the AuthMe Fabric port — the equivalent of the original plugin's main
 * class. Owns the configuration, messages, database, password-security, anti-bot and auth manager.
 */
public final class AuthMe {

    private static AuthMe instance;
    private static final String MESSAGE_TOKEN_PREFIX = "\u0001authme:";

    private MinecraftServer server;
    private AuthMeConfig config;
    private Messages messages;
    private DataSource dataSource;
    private PasswordSecurity passwordSecurity;
    private AuthManager authManager;
    private AntiBotManager antiBot;
    private GeoIpPolicy geoIp;
    private ProxyMessageSink proxyMessageSink;
    private volatile boolean healthy = false;

    public static AuthMe get() {
        return instance;
    }

    /** Returns the version declared by this build's Fabric metadata. */
    public static String version() {
        return FabricLoader.getInstance().getModContainer("authme")
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("unknown");
    }

    public static void set(AuthMe authMe) {
        instance = authMe;
    }

    /** @return the singleton, creating an empty one if not yet initialised (for early access). */
    public static AuthMe require() {
        if (instance == null) {
            instance = new AuthMe();
        }
        return instance;
    }

    public boolean init(MinecraftServer server) {
        this.server = server;
        Path configDir = FabricLoader.getInstance().getConfigDir().resolve("authme");
        this.config = new AuthMeConfig(configDir);
        if (!config.load()) {
            Log.error("Could not load config.yml; AuthMe cannot start safely.");
            failClosed(server, "configuration could not be loaded");

            return false;
        }
        try {
            config.validateSecurityConfiguration();
        } catch (RuntimeException e) {
            Log.error("Security-sensitive AuthMe configuration is invalid", e);
            failClosed(server, "security configuration is invalid");
            return false;
        }
        this.messages = new Messages(configDir, config.messagesLanguage());
        if (!messages.load()) {
            Log.error("Could not load messages.yml; AuthMe cannot start safely.");
            failClosed(server, "messages could not be loaded");
            return false;
        }
        this.geoIp = new GeoIpPolicy(config);

        try {
            this.passwordSecurity = new PasswordSecurity(
                config.passwordHash(),
                config.pbkdf2Rounds(),
                config.bcryptLog2Round(),
                config.doubleMD5SaltLength(),
                config.legacyHashes());
            DbSettings dbSettings = config.toDbSettings();
            if (passwordSecurity.getPrimaryMethod() == null) {
                Log.error("The configured passwordHash= CUSTOM has no external implementation.");
                failClosed(server, "password hashing is not configured");
                return false;
            }
            if (passwordSecurity.hasSeparateSalt() && !dbSettings.columns.hasSaltColumn()) {
                Log.error("The configured password algorithm requires DataSource.mySQLColumnSalt, but it is empty.");
                failClosed(server, "the password salt column is not configured");
                return false;
            }
            this.dataSource = wrapDataSource(createDataSource(dbSettings));
            if (!this.dataSource.ping()) {
                this.dataSource.close();
                this.dataSource = null;
                failClosed(server, "database health check failed");
                return false;
            }
            if (!migrateSessionSecurity()) {
                this.dataSource.close();
                this.dataSource = null;
                failClosed(server, "the session security migration failed");
                return false;
            }
        } catch (SQLException e) {
            Log.error("Could not initialise the database backend", e);
            failClosed(server, "database backend could not be initialised");
            return false;
        } catch (RuntimeException e) {
            DataSource failed = this.dataSource;
            this.dataSource = null;
            if (failed != null) {
                try { failed.close(); } catch (RuntimeException ignored) { }
            }
            Log.error("Could not initialise AuthMe because the configuration is invalid", e);
            failClosed(server, "the AuthMe configuration is invalid");
            return false;
        }

        this.antiBot = new AntiBotManager(config);
        this.authManager = new AuthManager(this);
        this.healthy = true;
        if (config.backupOnStart()) createLifecycleBackup("startup");
        Log.info("AuthMe Fabric ready. Backend=" + dataSource.getType()
            + " hashing=" + config.passwordHash() + " accounts=" + dataSource.countAuths());
        return true;
    }

    public boolean reload() {
        if (config == null) return false;
        AuthMeConfig nextConfig = new AuthMeConfig(config.configDir());
        if (!nextConfig.load()) { Log.error("AuthMe reload rejected: configuration could not be loaded."); return false; }
        try { nextConfig.validateSecurityConfiguration(); }
        catch (RuntimeException e) { Log.error("AuthMe reload rejected: security configuration is invalid", e); return false; }
        Messages nextMessages = new Messages(nextConfig.configDir(), nextConfig.messagesLanguage());
        if (!nextMessages.load()) { Log.error("AuthMe reload rejected: messages could not be loaded."); return false; }
        GeoIpPolicy nextGeoIp = new GeoIpPolicy(nextConfig);
        final PasswordSecurity nextPasswordSecurity;
        final DbSettings dbSettings;
        try {
            nextPasswordSecurity = new PasswordSecurity(nextConfig.passwordHash(), nextConfig.pbkdf2Rounds(),
                nextConfig.bcryptLog2Round(), nextConfig.doubleMD5SaltLength(), nextConfig.legacyHashes());
            dbSettings = nextConfig.toDbSettings();
        } catch (RuntimeException e) {
            Log.error("AuthMe reload rejected: database or password configuration is invalid", e);
            return false;
        }
        if (nextPasswordSecurity.getPrimaryMethod() == null || (nextPasswordSecurity.hasSeparateSalt() && !dbSettings.columns.hasSaltColumn())) {
            Log.error("AuthMe reload rejected: the configured password hash and salt storage are incompatible."); return false;
        }
        DataSource nextDataSource;
        try {
            nextDataSource = wrapDataSource(createDataSource(dbSettings), nextConfig);
            if (!nextDataSource.ping()) { nextDataSource.close(); Log.error("AuthMe reload rejected: database health check failed."); return false; }
            if (!migrateSessionSecurity(nextDataSource, nextConfig)) {
                nextDataSource.close();
                Log.error("AuthMe reload rejected: the session security migration failed.");
                return false;
            }
        } catch (SQLException e) {
            Log.error("Could not re-initialise the database backend after reload", e);
            return false;
        }
        DataSource oldDataSource = this.dataSource;
        this.config = nextConfig;
        this.messages = nextMessages;
        this.geoIp = nextGeoIp;
        this.passwordSecurity = nextPasswordSecurity;
        this.dataSource = nextDataSource;
        this.antiBot = new AntiBotManager(nextConfig);
        if (oldDataSource != null) oldDataSource.close();
        if (this.authManager == null) this.authManager = new AuthManager(this);
        else this.authManager.reloadConfiguration();
        this.healthy = true;
        Log.info("AuthMe reloaded.");
        return true;
    }

    private static void failClosed(MinecraftServer server, String reason) {
        Log.error("AuthMe is stopping the server because " + reason + ". Authentication must fail closed.");
        if (server != null) server.halt(false);
    }

    private boolean migrateSessionSecurity() {
        return migrateSessionSecurity(this.dataSource, this.config);
    }

    private boolean migrateSessionSecurity(DataSource source, AuthMeConfig sourceConfig) {
        Path marker = sourceConfig.configDir().resolve(".session-ip-binding-v2");
        String fingerprint = sessionDatabaseFingerprint(sourceConfig);
        try {
            if (Files.exists(marker) && Files.readString(marker).contains("fingerprint=" + fingerprint)) return true;
        } catch (Exception e) {
            Log.warn("Could not read the AuthMe session security marker; it will be recreated", e);
        }
        DataSource.OperationResult cleared = source.clearLoggedFlags();
        if (!cleared.successful()) return false;
        try {
            Files.writeString(marker, "Session IP binding migration completed.\nfingerprint=" + fingerprint + "\n");
        } catch (Exception e) {
            Log.warn("Could not persist the session security migration marker; it will be retried", e);
        }
        Log.warn("Cleared " + cleared.affected()
            + " stale login/session flags during the session security migration.");
        return true;
    }

    private static String sessionDatabaseFingerprint(AuthMeConfig sourceConfig) {
        DbSettings settings = sourceConfig.toDbSettings();
        String identity = String.join("|", String.valueOf(settings.backend), settings.host, settings.port,
            settings.user, settings.database, settings.table, sourceConfig.configDir().toAbsolutePath().normalize().toString(),
            settings.columns.NAME, settings.columns.IS_LOGGED, settings.columns.HAS_SESSION,
            settings.columns.LAST_IP, settings.columns.LAST_LOGIN);
        try {
            byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(identity.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private DataSource createDataSource(DbSettings s) throws SQLException {
        switch (s.backend) {
            case MYSQL: return new MySQLDataSource(s);
            case MARIADB: return new MariaDBDataSource(s);
            case POSTGRESQL: return new PostgreSqlDataSource(s);
            case SQLITE: return new SQLiteDataSource(s);
            default: return new SQLiteDataSource(s);
        }
    }

    private DataSource wrapDataSource(DataSource source) {
        return wrapDataSource(source, config);
    }

    private DataSource wrapDataSource(DataSource source, AuthMeConfig sourceConfig) {
        if (sourceConfig == null || !sourceConfig.dataSourceCaching()) return source;
        return new CachingDataSource(source, sourceConfig.cacheRefreshSeconds() * 1000L,
            sourceConfig.cacheExpireMinutes() * 60_000L);
    }

    public void shutdown() {
        if (config != null && dataSource != null && config.backupOnStop()) createLifecycleBackup("shutdown");
        if (dataSource != null) dataSource.close();
        healthy = false;
    }

    private void createLifecycleBackup(String label) {
        try {
            Path directory = config.configDir().resolve("backups");
            io.github.authme.fabric.util.SecureFileAccess.ensurePrivateDirectory(directory);
            Path file = directory.resolve("authme-" + label + "-" + System.currentTimeMillis() + ".sql");
            if (!dataSource.backup(file)) Log.error("Could not create AuthMe " + label + " backup at " + file);
            else Log.info("Created AuthMe " + label + " backup at " + file);
        } catch (Exception e) {
            Log.error("Could not create AuthMe " + label + " backup", e);
        }
    }

    public MinecraftServer server() { return server; }
    public AuthMeConfig config() { return config; }
    public Messages messages() { return messages; }
    public DataSource dataSource() { return dataSource; }
    public PasswordSecurity passwordSecurity() { return passwordSecurity; }

    public AuthManager authManager() { return authManager; }
    public AntiBotManager antiBot() { return antiBot; }
    public GeoIpPolicy geoIp() { return geoIp; }
    public boolean healthy() { return healthy; }

    /**
     * Runtime database failures must not leave an already running server in a
     * state where AuthMe can no longer verify credentials. The default policy
     * stops the server; when explicitly disabled, every online player is
     * disconnected and future joins are rejected until a successful reload.
     */
    public void databaseFailure(String reason) {
        if (!healthy) return;
        healthy = false;
        Log.error("AuthMe database failure: " + reason
            + ". Authentication is now fail-closed.");
        if (config != null && config.stopServerOnDbProblem()) {
            if (server != null) server.halt(false);
        } else if (authManager != null) {
            authManager.disconnectAllForDatabaseFailure();
        }
    }

    public void setProxyMessageSink(ProxyMessageSink sink) { this.proxyMessageSink = sink; }

    public void emitProxyMessage(String type, String playerName) {
        ProxyMessageSink sink = proxyMessageSink;
        if (sink != null && config != null && config.bungeecordHook()) sink.send(type, playerName);
    }

    public void emitProxyPremiumList(java.util.List<String> playerNames) {
        ProxyMessageSink sink = proxyMessageSink;
        if (sink != null && config != null && config.bungeecordHook()) sink.sendPremiumList(playerNames);
    }

    public void connectPlayerToConfiguredServer(ServerPlayer player) {
        if (config != null && config.bungeecordHook() && !config.bungeecordServer().isBlank()
            && !(config.permissionCheckEnabled()
                && Boolean.TRUE.equals(io.github.authme.fabric.util.PermissionBridge.check(
                    player == null ? null : player.getUUID(), "authme.bypassbungeesend")))) {
            io.github.authme.fabric.network.ProxyBridge.connect(server, player, config.bungeecordServer());
        }
    }

    public int addMissingMessages() {
        return messages == null ? -1 : messages.addMissingDefaults();
    }

    public String message(String key, Object... replacements) {
        if (messages == null || config == null || !config.perPlayerLocale()) {
            return messages == null ? "&c[AuthMe messages unavailable]" : messages.get(key, replacements);
        }
        StringBuilder token = new StringBuilder(MESSAGE_TOKEN_PREFIX)
            .append(encode(key == null ? "" : key));
        if (replacements != null) {
            for (Object replacement : replacements) token.append('.').append(encode(String.valueOf(replacement)));
        }
        return token.toString();
    }

    /** Resolves a message using the connected client's locale when enabled. */
    public String message(ServerPlayer player, String key, Object... replacements) {
        if (messages == null) return "&c[AuthMe messages unavailable]";
        if (player == null || config == null || !config.perPlayerLocale()) {
            return messages.get(key, replacements);
        }
        return messages.getForLocale(clientLocale(player), key, replacements);
    }

    /** Resolves an internal message token at the final output sink. */
    public String resolveMessage(ServerPlayer player, String value) {
        if (value == null || !value.startsWith(MESSAGE_TOKEN_PREFIX) || messages == null) return value;
        String encoded = value.substring(MESSAGE_TOKEN_PREFIX.length());
        String[] parts = encoded.split("\\.", -1);
        if (parts.length == 0) return value;
        try {
            String key = decode(parts[0]);
            Object[] replacements = new Object[Math.max(0, parts.length - 1)];
            for (int i = 1; i < parts.length; i++) replacements[i - 1] = decode(parts[i]);
            return message(player, key, replacements);
        } catch (IllegalArgumentException ignored) {
            return value;
        }
    }

    private static String encode(String value) {
        return java.util.Base64.getUrlEncoder().withoutPadding()
            .encodeToString(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static String decode(String value) {
        return new String(java.util.Base64.getUrlDecoder().decode(value), java.nio.charset.StandardCharsets.UTF_8);
    }

    private static String clientLocale(ServerPlayer player) {
        Object direct = invokeNoArg(player, "getLanguage");
        if (direct != null) return String.valueOf(direct);
        Object connection = field(player, "connection");
        Object info = invokeNoArg(connection, "getClientInformation", "clientInformation");
        Object language = invokeNoArg(info, "language", "getLanguage");
        return language == null ? "" : String.valueOf(language);
    }

    private static Object invokeNoArg(Object target, String... names) {
        if (target == null) return null;
        for (String name : names) {
            for (java.lang.reflect.Method method : target.getClass().getMethods()) {
                if (method.getName().equals(name) && method.getParameterCount() == 0) {
                    try { return method.invoke(target); } catch (ReflectiveOperationException | RuntimeException ignored) { }
                }
            }
        }
        return null;
    }

    private static Object field(Object target, String name) {
        if (target == null) return null;
        try {
            java.lang.reflect.Field field = target.getClass().getField(name);
            return field.get(target);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            try {
                java.lang.reflect.Field field = target.getClass().getDeclaredField(name);
                if (!field.canAccess(target)) field.setAccessible(true);
                return field.get(target);
            } catch (ReflectiveOperationException | RuntimeException ignoredToo) {
                return null;
            }
        }
    }
}
