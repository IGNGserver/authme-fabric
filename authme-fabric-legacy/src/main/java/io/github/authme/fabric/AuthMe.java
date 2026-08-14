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

    private MinecraftServer server;
    private AuthMeConfig config;
    private Messages messages;
    private DataSource dataSource;
    private PasswordSecurity passwordSecurity;
    private AuthManager authManager;
    private AntiBotManager antiBot;
    private GeoIpPolicy geoIp;
    private ProxyMessageSink proxyMessageSink;
    private boolean healthy = false;

    public static AuthMe get() {
        return instance;
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
        this.messages = new Messages(configDir, config.messagesLanguage());
        if (!messages.load()) {
            Log.error("Could not load messages.yml; AuthMe cannot start safely.");
            failClosed(server, "messages could not be loaded");
            return false;
        }
        this.geoIp = new GeoIpPolicy(config);

        this.passwordSecurity = new PasswordSecurity(
            config.passwordHash(),
            config.pbkdf2Rounds(),
            config.bcryptLog2Round(),
            config.doubleMD5SaltLength(),
            config.legacyHashes());
        try {
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
        } catch (SQLException e) {
            Log.error("Could not initialise the database backend", e);
            failClosed(server, "database backend could not be initialised");
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
        Messages nextMessages = new Messages(nextConfig.configDir(), nextConfig.messagesLanguage());
        if (!nextMessages.load()) { Log.error("AuthMe reload rejected: messages could not be loaded."); return false; }
        GeoIpPolicy nextGeoIp = new GeoIpPolicy(nextConfig);
        PasswordSecurity nextPasswordSecurity = new PasswordSecurity(nextConfig.passwordHash(), nextConfig.pbkdf2Rounds(),
            nextConfig.bcryptLog2Round(), nextConfig.doubleMD5SaltLength(), nextConfig.legacyHashes());
        DbSettings dbSettings = nextConfig.toDbSettings();
        if (nextPasswordSecurity.getPrimaryMethod() == null || (nextPasswordSecurity.hasSeparateSalt() && !dbSettings.columns.hasSaltColumn())) {
            Log.error("AuthMe reload rejected: the configured password hash and salt storage are incompatible."); return false;
        }
        DataSource nextDataSource;
        try {
            nextDataSource = wrapDataSource(createDataSource(dbSettings), nextConfig);
            if (!nextDataSource.ping()) { nextDataSource.close(); Log.error("AuthMe reload rejected: database health check failed."); return false; }
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
            Files.createDirectories(directory);
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
        return messages.get(key, replacements);
    }
}
