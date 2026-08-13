package io.github.authme.fabric.config;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.security.HashAlgorithm;
import io.github.authme.fabric.util.Log;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;
import org.yaml.snakeyaml.LoaderOptions;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Loads and exposes the AuthMe configuration (config.yml) and resolves it into a {@link DbSettings}.
 * Keys mirror AuthMeReloaded so an existing config.yml can be reused, and so a shared database with
 * the original plugin keeps working.
 */
public final class AuthMeConfig {

    private final Path configDir;
    private Map<String, Object> root = new LinkedHashMap<>();

    public AuthMeConfig(Path configDir) {
        this.configDir = configDir;
    }

    public boolean load() {
        try {
            Files.createDirectories(configDir);
            Path file = configDir.resolve("config.yml");
            if (!Files.exists(file)) {
                try (InputStream in = getClass().getResourceAsStream("/assets/authme/config.yml")) {
                    if (in == null) {
                        Log.error("Default config.yml missing from jar!");
                        return false;
                    }
                    try (OutputStream out = Files.newOutputStream(file)) {
                        in.transferTo(out);
                    }
                    Log.info("Created default config.yml at " + file);
                }
            }
            try (InputStream in = Files.newInputStream(file)) {
                Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
                Object loaded = yaml.load(in);
                if (loaded instanceof Map) {
                    //noinspection unchecked
                    root = (Map<String, Object>) loaded;
                }
            }
            return true;
        } catch (IOException | RuntimeException e) {
            Log.error("Could not load config.yml", e);
            return false;
        }
    }

    // -------------------------------------------------------- typed accessors

    public Object get(String path) {
        Object node = root;
        for (String key : path.split("\\.")) {
            if (node instanceof Map<?, ?> m) {
                node = m.get(key);
            } else {
                return null;
            }
            if (node == null) return null;
        }
        return node;
    }

    public String getString(String path, String def) {
        Object v = get(path);
        return v == null ? def : String.valueOf(v);
    }

    public int getInt(String path, int def) {
        Object v = get(path);
        if (v instanceof Number n) return n.intValue();
        if (v instanceof String s) { try { return Integer.parseInt(s.trim()); } catch (NumberFormatException ignored) { } }
        return def;
    }

    public boolean getBool(String path, boolean def) {
        Object v = get(path);
        if (v instanceof Boolean b) return b;
        if (v instanceof String s) return Boolean.parseBoolean(s.trim());
        return def;
    }

    public List<String> getStringList(String path) {
        Object v = get(path);
        if (v instanceof List<?> list) {
            List<String> out = new ArrayList<>();
            for (Object o : list) out.add(o == null ? "" : String.valueOf(o));
            return out;
        }
        return Collections.emptyList();
    }

    // -------------------------------------------------------- resolved groups

    public DataSourceType backend() {
        String b = getString("DataSource.backend", "SQLITE").trim().toUpperCase(Locale.ROOT);
        try {
            return DataSourceType.valueOf(b);
        } catch (IllegalArgumentException e) {
            Log.warn("Unknown DataSource.backend '" + b + "', defaulting to SQLITE");
            return DataSourceType.SQLITE;
        }
    }

    public DbSettings toDbSettings() {
        Columns columns = Columns.builder()
            .name(getString("DataSource.mySQLColumnName", "username"))
            .realName(getString("DataSource.mySQLRealName", "realname"))
            .password(getString("DataSource.mySQLColumnPassword", "password"))
            .salt(getString("DataSource.mySQLColumnSalt", ""))
            .totpKey(getString("DataSource.mySQLtotpKey", "totp"))
            .lastIp(getString("DataSource.mySQLColumnIp", "ip"))
            .lastLogin(getString("DataSource.mySQLColumnLastLogin", "lastlogin"))
            .group(getString("ExternalBoardOptions.mySQLColumnGroup", ""))
            .lastlocX(getString("DataSource.mySQLlastlocX", "x"))
            .lastlocY(getString("DataSource.mySQLlastlocY", "y"))
            .lastlocZ(getString("DataSource.mySQLlastlocZ", "z"))
            .lastlocWorld(getString("DataSource.mySQLlastlocWorld", "world"))
            .lastlocYaw(getString("DataSource.mySQLlastlocYaw", "yaw"))
            .lastlocPitch(getString("DataSource.mySQLlastlocPitch", "pitch"))
            .email(getString("DataSource.mySQLColumnEmail", "email"))
            .id(getString("DataSource.mySQLColumnId", "id"))
            .isLogged(getString("DataSource.mySQLColumnLogged", "isLogged"))
            .hasSession(getString("DataSource.mySQLColumnHasSession", "hasSession"))
            .regDate(getString("DataSource.mySQLColumnRegisterDate", "regdate"))
            .regIp(getString("DataSource.mySQLColumnRegisterIp", "regip"))
            .playerUuid(getString("DataSource.mySQLPlayerUUID", ""))
            .premiumUuid(getString("DataSource.mySQLColumnPremiumUUID", "premiumUUID"))
            .build();

        DataSourceType backend = backend();
        String database = getString("DataSource.mySQLDatabase", "authme");
        if (backend == DataSourceType.SQLITE) {
            // resolve SQLite db file under the config dir
            String name = database;
            if (name == null || name.isEmpty()) name = "authme";
            if (!name.toLowerCase(Locale.ROOT).endsWith(".db")) name = name + ".db";
            database = configDir.resolve(name).toAbsolutePath().toString();
        }

        return new DbSettings(
            backend,
            getString("DataSource.mySQLHost", "127.0.0.1"),
            getString("DataSource.mySQLPort", "3306"),
            getString("DataSource.mySQLUsername", "authme"),
            getString("DataSource.mySQLPassword", ""),
            database,
            getString("DataSource.mySQLTablename", "authme"),
            Math.max(2, getInt("DataSource.poolSize", 10)),
            getInt("DataSource.maxLifetime", 1800),
            getBool("DataSource.mySQLUseSSL", true),
            getBool("DataSource.mySQLCheckServerCertificate", true),
            getBool("DataSource.mySQLAllowPublicKeyRetrieval", true),
            columns
        );
    }

    // -------------------------------------------------------- security/registration/etc.

    public HashAlgorithm passwordHash() {
        return HashAlgorithm.parse(getString("settings.security.passwordHash", "SHA256"));
    }

    public List<HashAlgorithm> legacyHashes() {
        List<HashAlgorithm> out = new ArrayList<>();
        for (String s : getStringList("settings.security.legacyHashes")) {
            HashAlgorithm a = HashAlgorithm.parse(s);
            if (a != passwordHash()) out.add(a);
        }
        return out;
    }

    public int minPasswordLength() { return Math.max(1, getInt("settings.security.minPasswordLength", 5)); }
    public int maxPasswordLength() { return Math.max(minPasswordLength(), getInt("settings.security.passwordMaxLength", 30)); }
    public int pbkdf2Rounds() { return getInt("settings.security.pbkdf2Rounds", 10000); }
    public int bcryptLog2Round() { return getInt("ExternalBoardOptions.bCryptLog2Round", 10); }
    public int doubleMD5SaltLength() { return getInt("settings.security.doubleMD5SaltLength", 8); }
    public List<String> unsafePasswords() {
        List<String> l = getStringList("settings.security.unsafePasswords");
        List<String> out = new ArrayList<>(l.size());
        for (String s : l) out.add(s.toLowerCase(Locale.ROOT));
        return out;
    }

    public boolean stopServerOnDbProblem() { return getBool("Security.SQLProblem.stopServer", true); }
    public boolean captchaEnabled() { return getBool("Security.captcha.useCaptcha", false); }
    public int maxLoginTriesForCaptcha() { return getInt("Security.captcha.maxLoginTry", 5); }
    public int captchaLength() { return getInt("Security.captcha.captchaLength", 5); }
    public int captchaResetMinutes() { return getInt("Security.captcha.captchaCountReset", 60); }
    public boolean captchaForRegistration() { return getBool("Security.captcha.requireForRegistration", false); }
    public boolean tempbanEnabled() { return getBool("Security.tempban.enableTempban", false); }
    public int tempbanMaxLoginTries() { return getInt("Security.tempban.maxLoginTries", 10); }
    public int tempbanLengthMinutes() { return getInt("Security.tempban.tempbanLength", 480); }

    public boolean registrationEnabled() { return getBool("settings.registration.enabled", true); }
    public boolean registrationForce() { return getBool("settings.registration.force", true); }
    public int registrationTimeout() { return getInt("settings.registration.timeout", 120); }

    public boolean sessionEnabled() { return getBool("settings.session.enabled", false); }
    public int sessionTimeoutMinutes() { return getInt("settings.session.timeout", 60); }
    public boolean sessionOnlyIp() { return getBool("settings.session.sessionOnlyIp", false); }

    public boolean enablePremium() { return getBool("settings.enablePremium", false); }
    public boolean bungeecordHook() { return getBool("Hooks.bungeecord", false); }

    public boolean antiBotEnabled() { return getBool("AntiBot.enableAntiBot", false); }
    public int antiBotInterval() { return getInt("AntiBot.antibotInterval", 5); }
    public int antiBotThreshold() { return getInt("AntiBot.antibotThreshold", 8); }

    public boolean allowMovement() { return getBool("Settings.restrictUnauthenticated.allowMovement", false); }
    public double allowedMovementRadius() {
        Object v = get("Settings.restrictUnauthenticated.allowedMovementRadius");
        if (v instanceof Number n) return n.doubleValue();
        return 0.0d;
    }
    public boolean hideTablist() { return getBool("Settings.restrictUnauthenticated.hideTablist", false); }
    public List<String> allowedCommands() {
        List<String> base = getStringList("Settings.restrictUnauthenticated.allowCommands");
        if (base.isEmpty()) {
            base = new ArrayList<>();
            base.add("login"); base.add("register"); base.add("l"); base.add("reg");
            base.add("authme"); base.add("email"); base.add("2fa"); base.add("totp"); base.add("captcha");
        }
        return base;
    }
    public boolean saveQuitLocation() { return getBool("Settings.saveQuitLocation", true); }
    public int loginTimeout() { return getInt("Settings.timeouts.loginTimeout", 120); }
    public int registerTimeout() { return getInt("Settings.timeouts.registerTimeout", 120); }

    public Path configDir() { return configDir; }
}