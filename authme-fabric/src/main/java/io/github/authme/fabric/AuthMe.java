package io.github.authme.fabric;

import io.github.authme.fabric.auth.AuthManager;
import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.MariaDBDataSource;
import io.github.authme.fabric.datasource.MySQLDataSource;
import io.github.authme.fabric.datasource.PostgreSqlDataSource;
import io.github.authme.fabric.datasource.SQLiteDataSource;
import io.github.authme.fabric.security.PasswordSecurity;
import io.github.authme.fabric.util.Log;
import net.fabricmc.loader.api.FabricLoader;
import net.minecraft.server.MinecraftServer;

import java.nio.file.Path;
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
            Log.error("Could not load config.yml — AuthMe will be disabled.");
            return false;
        }
        this.messages = new Messages(configDir);
        messages.load();

        this.passwordSecurity = new PasswordSecurity(
            config.passwordHash(),
            config.pbkdf2Rounds(),
            config.bcryptLog2Round(),
            config.doubleMD5SaltLength(),
            config.legacyHashes());

        try {
            this.dataSource = createDataSource(config.toDbSettings());
        } catch (SQLException e) {
            Log.error("Could not initialise the database backend", e);
            if (config.stopServerOnDbProblem()) {
                Log.error("Stopping the server as configured (Security.SQLProblem.stopServer=true).");
                server.halt(false);
            }
            return false;
        }

        this.antiBot = new AntiBotManager(config);
        this.authManager = new AuthManager(this);
        this.healthy = true;
        Log.info("AuthMe Fabric ready. Backend=" + dataSource.getType()
            + " hashing=" + config.passwordHash() + " accounts=" + dataSource.countAuths());
        return true;
    }

    public void reload() {
        if (config == null) return;
        config.load();
        messages.load();
        this.passwordSecurity = new PasswordSecurity(
            config.passwordHash(),
            config.pbkdf2Rounds(),
            config.bcryptLog2Round(),
            config.doubleMD5SaltLength(),
            config.legacyHashes());
        if (dataSource != null) dataSource.close();
        try {
            this.dataSource = createDataSource(config.toDbSettings());
        } catch (SQLException e) {
            Log.error("Could not re-initialise the database backend after reload", e);
        }
        Log.info("AuthMe reloaded.");
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

    public void shutdown() {
        if (dataSource != null) dataSource.close();
        healthy = false;
    }

    public MinecraftServer server() { return server; }
    public AuthMeConfig config() { return config; }
    public Messages messages() { return messages; }
    public DataSource dataSource() { return dataSource; }
    public PasswordSecurity passwordSecurity() { return passwordSecurity; }
    public AuthManager authManager() { return authManager; }
    public AntiBotManager antiBot() { return antiBot; }
    public boolean healthy() { return healthy; }

    public String message(String key, Object... replacements) {
        return messages.get(key, replacements);
    }
}