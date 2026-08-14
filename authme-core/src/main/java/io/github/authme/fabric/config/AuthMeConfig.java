package io.github.authme.fabric.config;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
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
                if (!(loaded instanceof Map<?, ?> map)) {
                    Log.error("config.yml must contain a YAML mapping at its root");
                    return false;
                }
                //noinspection unchecked
                root = (Map<String, Object>) map;
                ensureWelcomeFile();
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

    /** Returns the first configured value. AuthMeReloaded has used both old and new paths. */
    private Object getAny(String... paths) {
        for (String path : paths) {
            Object value = get(path);
            if (value != null) return value;
        }
        return null;
    }

    private String getStringAny(String def, String... paths) {
        Object value = getAny(paths);
        return value == null ? def : String.valueOf(value);
    }

    private int getIntAny(int def, String... paths) {
        Object value = getAny(paths);
        if (value instanceof Number n) return n.intValue();
        if (value instanceof String s) {
            try { return Integer.parseInt(s.trim()); } catch (NumberFormatException ignored) { }
        }
        return def;
    }

    private double getDoubleAny(double def, String... paths) {
        Object value = getAny(paths);
        if (value instanceof Number n) return n.doubleValue();
        if (value instanceof String s) {
            try { return Double.parseDouble(s.trim()); } catch (NumberFormatException ignored) { }
        }
        return def;
    }

    private boolean getBoolAny(boolean def, String... paths) {
        Object value = getAny(paths);
        if (value instanceof Boolean b) return b;
        if (value instanceof String s) return Boolean.parseBoolean(s.trim());
        return def;
    }

    private List<String> getStringListAny(String... paths) {
        for (String path : paths) {
            if (get(path) != null) return getStringList(path);
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
            .salt(getString("DataSource.mySQLColumnSalt",
                getString("ExternalBoardOptions.mySQLColumnSalt", "")))
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
            getBoolAny(true, "DataSource.mySQLUseSSL", "DataSource.mysqlUseSSL"),
            getBoolAny(true, "DataSource.mySQLCheckServerCertificate", "DataSource.mysqlCheckServerCertificate"),
            getBoolAny(true, "DataSource.mySQLAllowPublicKeyRetrieval", "DataSource.mysqlAllowPublicKeyRetrieval"),
            columns
        );
    }

    // -------------------------------------------------------- security/registration/etc.

    public HashAlgorithm passwordHash() {
        return HashAlgorithm.parse(getStringAny("SHA256",
            "settings.security.passwordHash", "Security.passwordHash"));
    }

    public List<HashAlgorithm> legacyHashes() {
        List<HashAlgorithm> out = new ArrayList<>();
        for (String s : getStringListAny("settings.security.legacyHashes", "Security.legacyHashes")) {
            HashAlgorithm a = HashAlgorithm.parse(s);
            if (a != passwordHash()) out.add(a);
        }
        return out;
    }

    public int minPasswordLength() { return Math.max(1, getIntAny(5,
        "settings.security.minPasswordLength", "Settings.restrictions.minPasswordLength")); }
    public int maxPasswordLength() { return Math.max(minPasswordLength(), getIntAny(30,
        "settings.security.passwordMaxLength", "Settings.restrictions.maxPasswordLength")); }
    public int pbkdf2Rounds() { return getIntAny(10000, "settings.security.pbkdf2Rounds", "Security.pbkdf2Rounds"); }
    public int bcryptLog2Round() { return getIntAny(10, "ExternalBoardOptions.bCryptLog2Round"); }
    public int doubleMD5SaltLength() { return getIntAny(8, "settings.security.doubleMD5SaltLength"); }
    public List<String> unsafePasswords() {
        List<String> l = getAny("settings.security.unsafePasswords", "Settings.restrictions.unsafePasswords") == null
            ? List.of("123456", "password", "qwerty", "12345", "54321", "123456789", "help")
            : getStringListAny("settings.security.unsafePasswords", "Settings.restrictions.unsafePasswords");
        List<String> out = new ArrayList<>(l.size());
        for (String s : l) out.add(s.toLowerCase(Locale.ROOT));
        return out;
    }

    public boolean stopServerOnDbProblem() {
        return getBoolAny(true, "settings.security.SQLProblem.stopServer", "Security.SQLProblem.stopServer");
    }
    public boolean captchaEnabled() {
        return getBoolAny(false, "settings.security.captcha.useCaptcha", "Security.captcha.useCaptcha");
    }
    public int maxLoginTriesForCaptcha() {
        return getIntAny(5, "settings.security.captcha.maxLoginTry", "Security.captcha.maxLoginTry");
    }
    public int captchaLength() {
        return getIntAny(5, "settings.security.captcha.captchaLength", "Security.captcha.captchaLength");
    }
    public int captchaResetMinutes() {
        return getIntAny(60, "settings.security.captcha.captchaCountReset", "Security.captcha.captchaCountReset");
    }
    public boolean captchaForRegistration() {
        return getBoolAny(false, "settings.security.captcha.requireForRegistration",
            "Security.captcha.requireForRegistration");
    }
    public boolean tempbanEnabled() {
        return getBoolAny(false, "settings.security.tempban.enableTempban", "Security.tempban.enableTempban");
    }
    public int tempbanMaxLoginTries() {
        return getIntAny(10, "settings.security.tempban.maxLoginTries", "Security.tempban.maxLoginTries");
    }
    public int tempbanLengthMinutes() {
        return getIntAny(480, "settings.security.tempban.tempbanLength", "Security.tempban.tempbanLength");
    }
    public int tempbanCounterResetMinutes() {
        return getIntAny(480, "settings.security.tempban.minutesBeforeCounterReset",
            "Security.tempban.minutesBeforeCounterReset");
    }
    public String tempbanCustomCommand() { return getStringAny("",
        "settings.security.tempban.customCommand", "Security.tempban.customCommand"); }

    public boolean registrationEnabled() { return getBoolAny(true,
        "settings.registration.enabled", "Settings.registration.enabled"); }
    public boolean welcomeEnabled() { return getBoolAny(true,
        "settings.useWelcomeMessage", "settings.registration.useWelcomeMessage", "Settings.useWelcomeMessage"); }
    public boolean welcomeBroadcast() { return getBoolAny(false,
        "settings.broadcastWelcomeMessage", "settings.registration.broadcastWelcomeMessage", "Settings.broadcastWelcomeMessage"); }
    public boolean delayJoinMessage() { return getBoolAny(false,
        "settings.delayJoinMessage", "settings.registration.delayJoinMessage", "Settings.delayJoinMessage"); }
    public String customJoinMessage() { return getStringAny("",
        "settings.customJoinMessage", "settings.registration.customJoinMessage", "Settings.customJoinMessage"); }
    public boolean removeUnloggedLeaveMessage() { return getBoolAny(false,
        "settings.removeUnloggedLeaveMessage", "settings.registration.removeUnloggedLeaveMessage", "Settings.removeUnloggedLeaveMessage"); }
    public boolean removeJoinMessage() { return getBoolAny(false,
        "settings.removeJoinMessage", "settings.registration.removeJoinMessage", "Settings.removeJoinMessage"); }
    public boolean removeLeaveMessage() { return getBoolAny(false,
        "settings.removeLeaveMessage", "settings.registration.removeLeaveMessage", "Settings.removeLeaveMessage"); }
    public boolean applyBlindEffect() { return getBoolAny(false,
        "settings.applyBlindEffect", "settings.registration.applyBlindEffect", "Settings.applyBlindEffect"); }
    public Path welcomeFile() { return configDir.resolve("welcome.txt"); }
    public String serverName() { return getStringAny("Minecraft Server", "settings.serverName",
        "settings.registration.serverName", "Settings.serverName"); }
    public boolean registrationForce() { return getBoolAny(true,
        "settings.registration.force", "Settings.registration.force"); }
    public boolean preventOtherCase() { return getBoolAny(true,
        "settings.preventOtherCase", "Settings.registration.preventOtherCase"); }
    public int registrationTimeout() { return Math.max(0, getIntAny(30,
        "settings.restrictions.registerTimeout", "Settings.restrictions.registerTimeout",
        "settings.registration.timeout", "Settings.timeouts.registerTimeout", "Settings.restrictions.timeout")); }
    public boolean forcePortalAfterRegister() { return getBoolAny(false,
        "settings.registration.forcePortalAfterRegister", "Settings.restrictions.forcePortalAfterRegister"); }
    public boolean forceKickAfterRegister() { return getBoolAny(false,
        "settings.registration.forceKickAfterRegister", "Settings.registration.kickAfterRegister"); }
    public boolean forceLoginAfterRegister() { return getBoolAny(false,
        "settings.registration.forceLoginAfterRegister", "Settings.registration.loginAfterRegister"); }
    public int registrationKickDelaySeconds() { return Math.max(0, getIntAny(0,
        "settings.registration.delayForKicking", "Settings.restrictions.delayForKicking")); }
    public int registrationMessageThreshold() { return Math.max(0, getIntAny(0,
        "settings.registration.messageThreshold", "Settings.restrictions.messageThreshold")); }
    public int registrationMessageIntervalSeconds() { return Math.max(1, getIntAny(5,
        "settings.registration.messageInterval", "Registration.messageInterval")); }

    /**
     * AuthMeReloaded's registration mode.  The old boolean
     * {@code enableEmailRegistrationSystem} is still accepted for existing
     * installations which have not been migrated to the enum setting.
     */
    public RegistrationType registrationType() {
        Object configured = getAny("settings.registration.type", "Settings.registration.type");
        if (configured != null) return RegistrationType.parse(configured, RegistrationType.PASSWORD);
        Object legacy = getAny("settings.registration.enableEmailRegistrationSystem",
            "Settings.registration.enableEmailRegistrationSystem");
        return legacy == null || !asBoolean(legacy) ? RegistrationType.PASSWORD : RegistrationType.EMAIL;
    }

    /**
     * Resolves the AuthMe-compatible second {@code /register} argument mode,
     * including the pre-enum confirmation settings used by older releases.
     */
    public RegisterSecondaryArgument registrationSecondArgument() {
        Object configured = getAny("settings.registration.secondArg", "Settings.registration.secondArg");
        if (configured != null) {
            return RegisterSecondaryArgument.parse(configured, RegisterSecondaryArgument.CONFIRMATION);
        }
        Object legacyConfirmation = registrationType() == RegistrationType.EMAIL
            ? getAny("settings.registration.doubleEmailCheck", "Settings.registration.doubleEmailCheck")
            : getAny("settings.restrictions.enablePasswordConfirmation",
                "settings.restrictions.enablePasswordVerifier", "Settings.restrictions.enablePasswordConfirmation",
                "Settings.restrictions.enablePasswordVerifier");
        return legacyConfirmation == null || asBoolean(legacyConfirmation)
            ? RegisterSecondaryArgument.CONFIRMATION : RegisterSecondaryArgument.NONE;
    }

    public boolean requirePasswordConfirmation() {
        if (getAny("settings.registration.secondArg", "Settings.registration.secondArg") != null) {
            return registrationType() == RegistrationType.PASSWORD
                && registrationSecondArgument() == RegisterSecondaryArgument.CONFIRMATION;
        }
        return getBoolAny(true,
            "settings.restrictions.enablePasswordVerifier", "settings.registration.requirePasswordConfirmation",
            "Settings.restrictions.enablePasswordVerifier", "settings.restrictions.enablePasswordConfirmation",
            "Settings.restrictions.enablePasswordConfirmation");
    }

    /** AuthMeReloaded's server-wide message language setting. */
    public String messagesLanguage() { return getStringAny("en",
        "settings.messagesLanguage", "Settings.messagesLanguage", "settings.localization.language"); }

    /**
     * Post-join dialog UI is only consumed by platform modules that have native dialog packets.
     * AuthMeReloaded defaults this to enabled on supported server versions; modules without the
     * native packet API simply fall back to the chat flow.
     */
    public boolean dialogPostJoinEnabled() { return getBoolAny(true,
        "settings.registration.dialog.postJoin.enable", "settings.registration.useDialogUi",
        "settings.registration.dialog.enabled", "Settings.registration.useDialogUi"); }

    public boolean dialogShowForgotPasswordButton() { return getBoolAny(true,
        "settings.registration.dialog.showForgotPasswordButton",
        "settings.registration.dialog.showForgotPassword", "Settings.registration.dialog.showForgotPasswordButton"); }

    public boolean dialogShowBody() { return getBoolAny(true,
        "settings.registration.dialog.showBody", "Settings.registration.dialog.showBody"); }

    /** Paper/Folia-only upstream setting; retained for config compatibility and diagnostics. */
    public boolean dialogPreJoinEnabled() { return getBoolAny(false,
        "settings.registration.dialog.preJoin.enable", "settings.registration.usePreJoinDialogUi",
        "Settings.registration.dialog.preJoin.enable"); }

    public boolean dialogPreJoinShowCancelButton() { return getBoolAny(true,
        "settings.registration.dialog.preJoin.showCancelButton"); }

    public boolean dialogPreJoinAllowCloseWithEscape() { return getBoolAny(false,
        "settings.registration.dialog.preJoin.allowCloseWithEscape"); }

    public boolean dialogPreJoinRegisterCancelKicks() { return getBoolAny(false,
        "settings.registration.dialog.preJoin.registerCancelKicks"); }

    public boolean dialogPreJoinLoginCancelKicks() { return getBoolAny(true,
        "settings.registration.dialog.preJoin.loginCancelKicks"); }

    public boolean sessionEnabled() { return getBoolAny(false,
        "settings.session.enabled", "settings.sessions.enabled"); }
    public int sessionTimeoutMinutes() { return Math.max(0, getIntAny(60,
        "settings.session.timeout", "settings.sessions.timeout")); }
    public boolean sessionOnlyIp() { return getBoolAny(false,
        "settings.session.sessionOnlyIp", "settings.sessions.sessionOnlyIp",
        "settings.session.sessionExpireOnIpChange", "settings.sessions.sessionExpireOnIpChange"); }
    public boolean sessionExpireOnIpChange() { return getBoolAny(false,
        "settings.session.sessionExpireOnIpChange", "settings.sessions.sessionExpireOnIpChange"); }
    public boolean forceSingleSession() { return getBoolAny(true,
        "settings.restrictions.forceSingleSession", "Settings.restrictions.ForceSingleSession"); }

    public boolean enablePremium() { return getBoolAny(false, "settings.enablePremium", "settings.premium.enabled"); }
    public boolean bungeecordHook() { return getBoolAny(false, "Hooks.bungeecord", "Hooks.bungeecordHook"); }

    public String proxySharedSecret() { return getStringAny("", "Hooks.proxySharedSecret", "Hooks.proxySecret"); }
    public String bungeecordServer() { return getStringAny("", "Hooks.sendPlayerTo", "Hooks.bungeecordServer"); }

    public boolean dataSourceCaching() { return getBoolAny(true, "DataSource.caching", "DataSource.cacheEnabled"); }
    public int cacheRefreshSeconds() { return Math.max(1, getIntAny(300,
        "DataSource.cacheRefreshSeconds", "DataSource.cacheRefreshTime")); }
    public int cacheExpireMinutes() { return Math.max(1, getIntAny(15,
        "DataSource.cacheExpireMinutes", "DataSource.cacheExpireTime")); }

    // Legacy AuthMe restriction settings. These are intentionally exposed even when the Fabric
    // platform cannot emulate a Bukkit-specific hook; callers can then fail safely and explain why.
    public int maxRegistrationsPerIp() { return Math.max(0, getIntAny(1,
        "settings.registration.maxRegPerIp", "settings.restrictions.maxRegPerIp", "Settings.restrictions.maxRegPerIp")); }
    public int maxRegistrationsPerEmail() { return Math.max(0, getIntAny(1,
        "settings.registration.maxRegPerEmail", "settings.restrictions.maxRegPerEmail", "Email.maxRegPerEmail")); }
    public int maxLoginPerIp() { return Math.max(0, getIntAny(0,
        "settings.restrictions.maxLoginPerIp", "Settings.restrictions.maxLoginPerIp")); }
    public int maxJoinPerIp() { return Math.max(0, getIntAny(0,
        "settings.restrictions.maxJoinPerIp", "Settings.restrictions.maxJoinPerIp")); }
    public int minNicknameLength() { return Math.max(1, getIntAny(3,
        "settings.restrictions.minNicknameLength", "Settings.restrictions.minNicknameLength")); }
    public int maxNicknameLength() { return Math.max(minNicknameLength(), getIntAny(16,
        "settings.restrictions.maxNicknameLength", "Settings.restrictions.maxNicknameLength")); }
    public String allowedNicknameCharacters() { return getStringAny("^[A-Za-z0-9_]+$",
        "settings.restrictions.allowedNicknameCharacters", "Settings.restrictions.allowedNicknameCharacters"); }
    public String allowedPasswordCharacters() { return getStringAny("[!-~]*",
        "settings.restrictions.allowedPasswordCharacters", "Settings.restrictions.allowedPasswordCharacters"); }
    public boolean kickNonRegistered() { return getBoolAny(false,
        "settings.restrictions.kickNonRegistered", "Settings.restrictions.kickNonRegistered"); }
    public boolean kickOnWrongPassword() { return getBoolAny(true,
        "settings.restrictions.kickOnWrongPassword", "Settings.restrictions.kickOnWrongPassword"); }
    public boolean teleportUnauthenticatedToSpawn() { return getBoolAny(false,
        "settings.restrictions.teleportUnAuthedToSpawn", "Settings.restrictions.teleportUnAuthedToSpawn"); }
    public boolean forceSpawnOnJoin() { return getBoolAny(false,
        "settings.restrictions.ForceSpawnLocOnJoin.enabled", "settings.restrictions.forceSpawnLocOnJoinEnabled",
        "Settings.restrictions.ForceSpawnLocOnJoin.enabled", "Settings.restrictions.forceSpawnLocOnJoinEnabled"); }
    public List<String> forceSpawnWorlds() { return getStringListAny(
        "settings.restrictions.ForceSpawnLocOnJoin.worlds", "Settings.restrictions.ForceSpawnLocOnJoin.worlds"); }
    public boolean noTeleport() { return getBoolAny(false,
        "settings.restrictions.noTeleport", "Settings.restrictions.noTeleport"); }
    public boolean allowChat() { return getBoolAny(false,
        "settings.restrictUnauthenticated.allowChat", "settings.restrictions.allowChat", "Settings.restrictUnauthenticated.allowChat"); }
    public boolean protectInventoryBeforeLogin() { return getBoolAny(true,
        "settings.restrictUnauthenticated.protectInventory", "settings.restrictions.ProtectInventoryBeforeLogIn", "Settings.restrictUnauthenticated.protectInventory"); }
    public boolean denyTabCompleteBeforeLogin() { return getBoolAny(false,
        "settings.restrictions.DenyTabCompleteBeforeLogin", "Settings.restrictUnauthenticated.DenyTabCompleteBeforeLogin",
        "Settings.restrictUnauthenticated.denyTabCompleteBeforeLogin"); }
    public boolean removeSpeed() { return getBoolAny(false,
        "settings.restrictions.removeSpeed", "Settings.restrictions.removeSpeed"); }
    public boolean displayOtherAccounts() { return getBoolAny(true,
        "settings.restrictions.displayOtherAccounts", "Settings.restrictions.displayOtherAccounts"); }
    public int otherAccountsThreshold() { return Math.max(0, getIntAny(0,
        "settings.restrictions.otherAccountsThreshold", "settings.restrictions.otherAccountsCmdThreshold",
        "Settings.restrictions.otherAccountsThreshold", "Settings.restrictions.otherAccountsCmdThreshold")); }
    public boolean banUnsafeIp() { return getBoolAny(false,
        "settings.restrictions.banUnsafedIP", "Settings.restrictions.banUnsafedIP"); }
    public boolean allowRestrictedUsers() { return getBoolAny(false,
        "settings.restrictions.AllowRestrictedUser", "Settings.restrictions.AllowRestrictedUser"); }
    public List<String> allowedRestrictedUsers() { return getStringListAny(
        "settings.restrictions.AllowedRestrictedUser", "Settings.restrictions.AllowedRestrictedUser"); }
    public List<String> unrestrictedNames() { return getStringListAny(
        "settings.unrestrictions.UnrestrictedName", "Settings.unrestrictions.UnrestrictedName"); }
    public String otherAccountsCommand() { return getStringAny("",
        "settings.restrictions.otherAccountsCmd", "Settings.restrictions.otherAccountsCmd"); }
    public int otherAccountsCommandThreshold() { return Math.max(2, getIntAny(0,
        "settings.restrictions.otherAccountsCmdThreshold", "Settings.restrictions.otherAccountsCmdThreshold")); }

    public boolean emailEnabled() {
        Object explicit = getAny("Email.enabled", "settings.email.enabled");
        return explicit == null ? !emailUsername().isBlank() : getBoolAny(false, "Email.enabled", "settings.email.enabled");
    }
    /** AuthMe email registration requires a sender account, even when a relay does not require AUTH. */
    public boolean emailRegistrationConfigured() {
        return emailEnabled() && !emailUsername().isBlank() && !emailPassword().isBlank();
    }
    public String emailHost() { return getStringAny("127.0.0.1", "Email.host", "Email.mailSMTP"); }
    public int emailPort() { return Math.max(1, getIntAny(25, "Email.port", "Email.mailPort")); }
    public String emailUsername() { return getStringAny("", "Email.username", "Email.mailAccount"); }
    public String emailPassword() { return getStringAny("", "Email.password", "Email.mailPassword"); }
    public String emailFrom() {
        String configured = getStringAny("", "Email.from", "Email.mailAddress").trim();
        if (!configured.isEmpty()) return configured;
        return emailUsername();
    }
    public boolean emailSsl() { return getBoolAny(false, "Email.ssl", "Email.sslCheckServerIdentity"); }
    public boolean emailStartTls() { return getBoolAny(true, "Email.startTls"); }
    public int emailTimeoutMillis() { return Math.max(1000, getIntAny(10000, "Email.timeoutMillis")); }
    public int emailGeneratedPasswordLength() {
        return Math.max(1, getIntAny(8, "Email.RecoveryPasswordLength", "Email.recoveryPasswordLength",
            "Email.generatedPasswordLength"));
    }
    public int emailRecoveryTimeoutSeconds() {
        // AuthMeReloaded's legacy delayRecall is expressed in minutes; the
        // native compatibility key is expressed in seconds.
        if (getAny("Email.recoveryTimeoutSeconds") != null) {
            return Math.max(60, getIntAny(600, "Email.recoveryTimeoutSeconds"));
        }
        return Math.max(60, getIntAny(10, "Email.delayRecall") * 60);
    }
    public boolean emailRequireVerification() { return getBoolAny(false, "Email.requireVerification", "Email.requireEmail"); }
    public String emailSenderName() { return getStringAny("AuthMe", "Email.senderName", "Email.mailSenderName"); }
    public String emailSubject() { return getStringAny("AuthMe", "Email.subject", "Email.mailSubject"); }
    public List<String> emailBlacklist() { return getStringListAny("Email.blacklistedDomains", "Email.emailBlacklisted"); }
    public List<String> emailWhitelist() { return getStringListAny("Email.whitelistedDomains", "Email.emailWhitelisted"); }

    private static boolean asBoolean(Object value) {
        if (value instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(value).trim());
    }

    public boolean antiBotEnabled() { return getBoolAny(false, "AntiBot.enableAntiBot", "Protection.enableAntiBot"); }
    public int antiBotInterval() { return Math.max(1, getIntAny(5, "AntiBot.antibotInterval", "Protection.antiBotInterval")); }
    public int antiBotThreshold() { return Math.max(1, getIntAny(8,
        "AntiBot.antibotThreshold", "Protection.antiBotThreshold", "Protection.antiBotSensibility")); }
    public int antiBotDurationMinutes() { return Math.max(1, getIntAny(10,
        "AntiBot.antibotDuration", "Protection.antiBotDuration")); }
    public int antiBotDelaySeconds() { return Math.max(0, getIntAny(60,
        "AntiBot.antibotDelay", "Protection.antiBotDelay")); }
    public List<String> antiBotCommands() { return getStringListAny("AntiBot.antibotCommands", "Protection.antiBotCommands"); }

    public boolean geoIpEnabled() { return getBoolAny(true, "Protection.geoIpDatabase.enabled", "Protection.geoIpEnabled"); }
    public boolean geoIpFailClosed() { return getBoolAny(false, "Protection.geoIpDatabase.failClosed", "Protection.geoIpFailClosed"); }
    public List<String> geoIpWhitelist() { return getStringListAny("Protection.countries", "Protection.countriesWhitelist"); }
    public List<String> geoIpBlacklist() { return getStringListAny("Protection.countriesBlacklist", "Protection.countryBlacklist"); }
    public Path geoIpFile() {
        String configured = getStringAny("geoip-countries.csv", "Protection.geoIpDatabase.file",
            "Protection.geoIpDatabase.mappingFile").trim();
        try {
            Path path = Path.of(configured);
            return path.isAbsolute() ? path.normalize() : configDir.resolve(path).normalize();
        } catch (RuntimeException e) {
            Log.warn("Invalid GeoIP database path in configuration; using the default mapping file");
            return configDir.resolve("geoip-countries.csv");
        }
    }
    public boolean protectionEnabled() { return getBoolAny(false, "Protection.enableProtection", "settings.security.enableProtection"); }
    public boolean protectionRegistered() { return getBoolAny(true, "Protection.enableProtectionRegistered"); }

    public boolean allowMovement() { return getBoolAny(false,
        "Settings.restrictUnauthenticated.allowMovement", "settings.restrictions.allowMovement"); }
    public double allowedMovementRadius() {
        return Math.max(0.0d, getDoubleAny(100.0d,
            "Settings.restrictUnauthenticated.allowedMovementRadius", "settings.restrictions.allowedMovementRadius"));
    }
    public boolean hideTablist() { return getBoolAny(false,
        "Settings.restrictUnauthenticated.hideTablist", "settings.restrictions.hideTablist"); }
    public boolean hideChat() { return getBoolAny(false,
        "settings.restrictions.hideChat", "Settings.restrictUnauthenticated.hideChat"); }
    public boolean permissionCheckEnabled() { return getBoolAny(true,
        "settings.permission.EnablePermissionCheck", "Permission.EnablePermissionCheck",
        "Permission.enablePermissionCheck", "Settings.permission.EnablePermissionCheck"); }
    public boolean forceSurvivalMode() { return getBoolAny(false,
        "settings.GameMode.ForceSurvivalMode", "Settings.GameMode.ForceSurvivalMode"); }
    public boolean forceSurvivalOnlyAfterLogin() { return getBoolAny(false,
        "settings.GameMode.ForceOnlyAfterLogin", "Settings.GameMode.ForceOnlyAfterLogin"); }
    public boolean resetInventoryIfCreative() { return getBoolAny(false,
        "settings.GameMode.ResetInventoryIfCreative", "Settings.GameMode.ResetInventoryIfCreative"); }
    public boolean restrictUnauthenticated() { return getBoolAny(true,
        "Settings.restrictUnauthenticated.enabled", "settings.restrictions.enableProtection"); }
    public List<String> allowedCommands() {
        List<String> base = getStringListAny("Settings.restrictUnauthenticated.allowCommands",
            "settings.restrictions.allowCommands");
        if (base.isEmpty()) {
            base = new ArrayList<>();
            base.add("login"); base.add("register"); base.add("l"); base.add("reg");
            base.add("authme"); base.add("email"); base.add("2fa"); base.add("totp"); base.add("captcha");
        }
        return base;
    }
    public boolean saveQuitLocation() { return getBoolAny(false,
        "Settings.saveQuitLocation", "settings.restrictions.SaveQuitLocation"); }
    public int loginTimeout() { return Math.max(0, getIntAny(30,
        "settings.restrictions.loginTimeout", "Settings.restrictions.loginTimeout",
        "Settings.timeouts.loginTimeout", "settings.restrictions.timeout")); }
    public int registerTimeout() { return registrationTimeout(); }
    public boolean databaseCacheEnabled() { return dataSourceCaching(); }

    public boolean backupEnabled() { return getBoolAny(false, "BackupSystem.ActivateBackup", "BackupSystem.enabled"); }
    public boolean backupOnStart() { return getBoolAny(false, "BackupSystem.OnServerStart", "BackupSystem.onStart"); }
    public boolean backupOnStop() { return getBoolAny(false, "BackupSystem.OnServerStop", "BackupSystem.onStop"); }
    public int backupIntervalHours() { return Math.max(0, getIntAny(0, "BackupSystem.Time", "BackupSystem.intervalHours")); }
    public boolean purgeEnabled() { return getBoolAny(false, "Purge.enabled", "Purge.ActivatePurge", "Purge.useAutoPurge"); }
    public int purgeDays() { return Math.max(1, getIntAny(30,
        "Purge.days", "Purge.PurgeTime", "Purge.daysBeforeRemovePlayer")); }
    public boolean purgeBannedPlayers() { return getBoolAny(false, "Purge.purgeBannedPlayers"); }
    public boolean purgeRemovePlayerDat() { return getBoolAny(false, "Purge.removePlayerDat"); }
    public boolean purgeRemoveEssentialsFile() { return getBoolAny(false,
        "Purge.removeEssentialsFile", "Purge.removeEssentialsFiles"); }
    public String purgeDefaultWorld() { return getStringAny("world", "Purge.defaultWorld"); }
    public boolean purgeRemoveLimitedCreativeInventories() { return getBoolAny(false,
        "Purge.removeLimitedCreativesInventories", "Purge.removeLimitedCreativeInventories"); }
    public boolean purgeRemoveAntiXrayFile() { return getBoolAny(false, "Purge.removeAntiXRayFile"); }
    public boolean purgeRemovePermissions() { return getBoolAny(false, "Purge.removePermissions"); }
    public Path eventCommandsFile() { return configDir.resolve("commands.yml"); }

    public Path configDir() { return configDir; }

    private void ensureWelcomeFile() {
        if (Files.exists(welcomeFile())) return;
        try (InputStream in = getClass().getResourceAsStream("/assets/authme/welcome.txt")) {
            if (in != null) {
                Files.write(welcomeFile(), in.readAllBytes());
            }
        } catch (IOException | RuntimeException e) {
            Log.warn("Could not create optional AuthMe welcome.txt", e);
        }
    }

}
