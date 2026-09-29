package io.github.authme.proxy.core;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.util.SecureFileAccess;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Platform-neutral proxy configuration and validation.
 *
 * <p>The proxy config is intentionally separate from the backend AuthMe config.
 * A proxy cannot trust arbitrary YAML types or an empty HMAC secret.  Missing
 * secrets are generated into a private sidecar file so a fresh installation is
 * safe by default and the operator has an explicit value to copy to every backend.</p>
 */
public final class ProxyConfig {

    private static final int MAX_SERVER_NAMES = 128;
    private static final int MAX_COMMANDS = 128;
    private static final int MAX_YAML_CODE_POINTS = 256 * 1024;
    private static final int MAX_FLAT_CONFIG_VALUES = 512;
    private static final int MAX_CONFIG_KEY_LENGTH = 128;
    private static final int MAX_CONFIG_NESTING = 16;
    private static final int MAX_SECRET_LENGTH = 256;
    private static final int MIN_SECRET_LENGTH = 16;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Set<String> authServers;
    private final boolean allServersAreAuthServers;
    private final boolean serverSwitchRequiresAuth;
    private final String serverSwitchKickMessage;
    private final boolean autoLogin;
    private final boolean sendOnLogout;
    private final String unloggedUserServer;
    private final boolean commandsRequireAuth;
    private final Set<String> commandWhitelist;
    private final boolean chatRequiresAuth;
    private final String loginServer;
    private final String sharedSecret;
    private final boolean keepOfflineUuidCompatibility;
    private final Map<String, BackendCredential> backendCredentials;
    private final boolean premiumEnabled;
    private final DbSettings premiumDatabase;
    private final String premiumLookupFailureMessage;

    private ProxyConfig(Set<String> authServers, boolean allServersAreAuthServers,
                        boolean serverSwitchRequiresAuth, String serverSwitchKickMessage,
                        boolean autoLogin, boolean sendOnLogout, String unloggedUserServer,
                        boolean commandsRequireAuth, Set<String> commandWhitelist,
                        boolean chatRequiresAuth, String loginServer, String sharedSecret,
                        boolean keepOfflineUuidCompatibility,
                        Map<String, BackendCredential> backendCredentials,
                        boolean premiumEnabled, DbSettings premiumDatabase,
                        String premiumLookupFailureMessage) {
        this.authServers = Set.copyOf(authServers);
        this.allServersAreAuthServers = allServersAreAuthServers;
        this.serverSwitchRequiresAuth = serverSwitchRequiresAuth;
        this.serverSwitchKickMessage = boundedMessage(serverSwitchKickMessage);
        this.autoLogin = autoLogin;
        this.sendOnLogout = sendOnLogout;
        this.unloggedUserServer = normalizeServerName(unloggedUserServer);
        this.commandsRequireAuth = commandsRequireAuth;
        this.commandWhitelist = Set.copyOf(commandWhitelist);
        this.chatRequiresAuth = chatRequiresAuth;
        this.loginServer = normalizeServerName(loginServer);
        this.sharedSecret = requireSecret(sharedSecret);
        this.keepOfflineUuidCompatibility = keepOfflineUuidCompatibility;
        this.backendCredentials = Map.copyOf(backendCredentials);
        this.premiumEnabled = premiumEnabled;
        this.premiumDatabase = premiumDatabase;
        this.premiumLookupFailureMessage = boundedMessage(premiumLookupFailureMessage);
    }

    public static ProxyConfig load(Path dataDirectory) throws IOException {
        SecureFileAccess.ensurePrivateDirectory(dataDirectory);
        Path configFile = dataDirectory.resolve("config.yml");
        if (!Files.exists(configFile, LinkOption.NOFOLLOW_LINKS)) {
            try (OutputStream output = SecureFileAccess.createNewPrivateFile(configFile)) {
                output.write(defaultConfig().getBytes(StandardCharsets.UTF_8));
            }
        } else {
            SecureFileAccess.harden(configFile);
        }
        Map<String, Object> root = readMap(configFile);
        resolveRelativePremiumDatabase(root, dataDirectory);
        String secret = string(root, "proxySharedSecret", "");
        if (secret.isBlank()) {
            secret = loadOrCreateSecret(dataDirectory);
        }
        return from(root, secret);
    }

    public static ProxyConfig from(Map<String, Object> root, String sharedSecret) {
        List<String> configuredServers = strings(root, "authServers", List.of("lobby"));
        Set<String> authServers = normalizeServers(configuredServers);
        boolean allServersAreAuthServers = bool(root, "allServersAreAuthServers", false);
        if (allServersAreAuthServers) {
            throw new IllegalArgumentException("allServersAreAuthServers is not compatible with per-backend trust; list authServers explicitly");
        }
        if (authServers.isEmpty()) {
            throw new IllegalArgumentException("At least one explicit authServers entry is required");
        }
        Map<String, BackendCredential> backendCredentials = parseBackendCredentials(
            root, authServers, sharedSecret);
        boolean premiumEnabled = bool(root, "premium.enabled", false);
        DbSettings premiumDatabase = premiumEnabled ? parsePremiumDatabase(root) : null;
        Set<String> whitelist = normalizeCommands(strings(root, "commands.whitelist",
            List.of("/login", "/register", "/l", "/reg", "/email", "/captcha", "/2fa", "/totp", "/log")));
        return new ProxyConfig(
            authServers,
            false,
            bool(root, "serverSwitch.requiresAuth", true),
            string(root, "serverSwitch.kickMessage", "Authentication required."),
            bool(root, "autoLogin", false),
            bool(root, "sendOnLogout", false),
            string(root, "unloggedUserServer", ""),
            bool(root, "commands.requireAuth", true),
            whitelist,
            bool(root, "chatRequiresAuth", true),
            string(root, "loginServer", ""),
            sharedSecret,
            bool(root, "premium.keepOfflineUuidCompatibility", false),
            backendCredentials,
            premiumEnabled,
            premiumDatabase,
            string(root, "premium.lookupFailureMessage",
                "Premium account verification is temporarily unavailable."));
    }

    public Set<String> authServers() { return authServers; }
    public boolean allServersAreAuthServers() { return allServersAreAuthServers; }
    public boolean serverSwitchRequiresAuth() { return serverSwitchRequiresAuth; }
    public String serverSwitchKickMessage() { return serverSwitchKickMessage; }
    public boolean autoLogin() { return autoLogin; }
    public boolean sendOnLogout() { return sendOnLogout; }
    public String unloggedUserServer() { return unloggedUserServer; }
    public boolean commandsRequireAuth() { return commandsRequireAuth; }
    public boolean chatRequiresAuth() { return chatRequiresAuth; }
    public String loginServer() { return loginServer; }
    public String sharedSecret() { return sharedSecret; }
    public boolean keepOfflineUuidCompatibility() { return keepOfflineUuidCompatibility; }
    public boolean premiumEnabled() { return premiumEnabled; }
    public DbSettings premiumDatabase() { return premiumDatabase; }
    public String premiumLookupFailureMessage() { return premiumLookupFailureMessage; }

    public BackendCredential backendCredential(String serverName) {
        return backendCredentials.get(normalizeServerName(serverName));
    }

    /** Verifies the cryptographic identity inside a message against its physical proxy source. */
    public boolean acceptsBackendIdentity(String serverName, String backendId) {
        BackendCredential credential = backendCredential(serverName);
        return credential != null
            && credential.backendId().equals(normalizeServerName(backendId));
    }

    public boolean isAuthServer(String serverName) {
        return allServersAreAuthServers || authServers.contains(normalizeServerName(serverName));
    }

    public boolean isWhitelistedCommand(String command) {
        return commandWhitelist.contains(normalizeCommand(command));
    }

    public record BackendCredential(String backendId, String secret) {
        public BackendCredential {
            backendId = normalizeServerName(backendId);
            if (backendId.isEmpty()) throw new IllegalArgumentException("Backend ID is invalid");
            secret = requireSecret(secret);
        }
    }

    public static String normalizeServerName(String value) {
        if (value == null) return "";
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return normalized.matches("[a-z0-9_.-]{1,64}") ? normalized : "";
    }

    public static String normalizeCommand(String command) {
        if (command == null) return "";
        String trimmed = command.trim();
        if (trimmed.isEmpty()) return "";
        int end = trimmed.indexOf(' ');
        String alias = end < 0 ? trimmed : trimmed.substring(0, end);
        if (!alias.startsWith("/")) alias = "/" + alias;
        return alias.toLowerCase(Locale.ROOT);
    }

    private static Map<String, Object> readMap(Path file) throws IOException {
        Object parsed;
        try (InputStream input = Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS)) {
            LoaderOptions options = new LoaderOptions();
            options.setCodePointLimit(MAX_YAML_CODE_POINTS);
            options.setMaxAliasesForCollections(16);
            options.setNestingDepthLimit(16);
            parsed = new Yaml(new SafeConstructor(options)).load(input);
        }
        if (!(parsed instanceof Map<?, ?> map)) {
            throw new IOException("Proxy config root must be a YAML mapping");
        }
        return flattenKeys(map);
    }

    private static Map<String, Object> flattenKeys(Map<?, ?> source) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : source.entrySet()) {
            if (entry.getKey() == null || out.size() >= MAX_FLAT_CONFIG_VALUES) break;
            String key = String.valueOf(entry.getKey());
            if (key.length() > MAX_CONFIG_KEY_LENGTH) continue;
            flattenInto(out, key, entry.getValue(), 0);
        }
        return out;
    }

    private static void flattenInto(Map<String, Object> out, String prefix, Object value, int depth) {
        if (out.size() >= MAX_FLAT_CONFIG_VALUES || prefix.length() > MAX_CONFIG_KEY_LENGTH
            || depth > MAX_CONFIG_NESTING) return;
        if (value instanceof Map<?, ?> map) {
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                if (entry.getKey() == null || out.size() >= MAX_FLAT_CONFIG_VALUES) break;
                String key = String.valueOf(entry.getKey());
                if (key.length() > MAX_CONFIG_KEY_LENGTH) continue;
                flattenInto(out, prefix + "." + key, entry.getValue(), depth + 1);
            }
        } else {
            out.put(prefix, value);
        }
    }

    private static String string(Map<String, Object> root, String key, String fallback) {
        Object value = root.get(key);
        return value == null ? fallback : String.valueOf(value).trim();
    }

    private static boolean bool(Map<String, Object> root, String key, boolean fallback) {
        Object value = root.get(key);
        if (value instanceof Boolean bool) return bool;
        return value == null ? fallback : Boolean.parseBoolean(String.valueOf(value).trim());
    }

    private static List<String> strings(Map<String, Object> root, String key, List<String> fallback) {
        Object value = root.get(key);
        if (!(value instanceof Collection<?> collection)) return fallback;
        List<String> values = new ArrayList<>();
        for (Object item : collection) if (item != null && values.size() < MAX_SERVER_NAMES) values.add(String.valueOf(item));
        return values;
    }

    private static Set<String> normalizeServers(Collection<String> values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String value : values) {
            String normalized = normalizeServerName(value);
            if (!normalized.isEmpty() && result.size() < MAX_SERVER_NAMES) result.add(normalized);
        }
        return result;
    }

    private static Set<String> normalizeCommands(Collection<String> values) {
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String value : values) {
            String normalized = normalizeCommand(value);
            if (!normalized.isEmpty() && result.size() < MAX_COMMANDS) result.add(normalized);
        }
        return result;
    }

    private static Map<String, BackendCredential> parseBackendCredentials(
        Map<String, Object> root, Set<String> authServers, String sharedSecret) {
        LinkedHashSet<String> configured = new LinkedHashSet<>();
        String prefix = "backendCredentials.";
        for (String key : root.keySet()) {
            if (!key.startsWith(prefix)) continue;
            String remainder = key.substring(prefix.length());
            int separator = remainder.indexOf('.');
            if (separator <= 0) continue;
            String server = normalizeServerName(remainder.substring(0, separator));
            if (!server.isEmpty()) configured.add(server);
        }

        // A single-backend legacy configuration can be upgraded safely because there is only one
        // physical source to bind. Multiple auth backends must always be explicit.
        if (configured.isEmpty()) {
            if (authServers.size() != 1) {
                throw new IllegalArgumentException(
                    "Multiple authServers require backendCredentials.<server>.backendId and .secret entries");
            }
            String server = authServers.iterator().next();
            return Map.of(server, new BackendCredential("backend", sharedSecret));
        }

        LinkedHashMap<String, BackendCredential> result = new LinkedHashMap<>();
        for (String server : configured) {
            String backendId = string(root, prefix + server + ".backendId", "");
            String secret = string(root, prefix + server + ".secret", "");
            if (secret.isBlank() && configured.size() == 1) secret = sharedSecret;
            result.put(server, new BackendCredential(backendId, secret));
        }
        for (String authServer : authServers) {
            if (!result.containsKey(authServer)) {
                throw new IllegalArgumentException("Missing backendCredentials for auth server " + authServer);
            }
        }
        return result;
    }

    private static DbSettings parsePremiumDatabase(Map<String, Object> root) {
        String rawBackend = string(root, "premium.database.backend", "").toUpperCase(Locale.ROOT);
        DataSourceType backend;
        try {
            backend = DataSourceType.valueOf(rawBackend);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                "premium.database.backend must be SQLITE, MYSQL, MARIADB or POSTGRESQL", exception);
        }
        String database = string(root, "premium.database.database", "");
        if (database.isBlank()) throw new IllegalArgumentException("premium.database.database is required");
        String table = string(root, "premium.database.table", "authme");
        String premiumColumn = string(root, "premium.database.columns.premiumUuid", "premiumUUID");
        if (premiumColumn.isBlank()) {
            throw new IllegalArgumentException("premium.database.columns.premiumUuid is required");
        }
        String rawTls = string(root, "premium.database.tlsMode", "VERIFY_IDENTITY").toUpperCase(Locale.ROOT);
        DbSettings.TlsMode tlsMode;
        try {
            tlsMode = DbSettings.TlsMode.valueOf(rawTls);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                "premium.database.tlsMode must be DISABLED, REQUIRED, VERIFY_CA or VERIFY_IDENTITY", exception);
        }
        boolean remote = backend != DataSourceType.SQLITE;
        String host = string(root, "premium.database.host", "127.0.0.1");
        String port = string(root, "premium.database.port", switch (backend) {
            case MYSQL, MARIADB -> "3306";
            case POSTGRESQL -> "5432";
            case SQLITE -> "";
        });
        String user = string(root, "premium.database.user", "");
        if (remote && user.isBlank()) {
            throw new IllegalArgumentException("premium.database.user must be a SELECT-only database account");
        }
        Columns columns = Columns.builder()
            .name(string(root, "premium.database.columns.username", "username"))
            .premiumUuid(premiumColumn)
            .build();
        return new DbSettings(backend, host, port, user,
            string(root, "premium.database.password", ""), database, table, 2, 300,
            tlsMode != DbSettings.TlsMode.DISABLED,
            tlsMode == DbSettings.TlsMode.VERIFY_CA || tlsMode == DbSettings.TlsMode.VERIFY_IDENTITY,
            false, tlsMode, columns);
    }

    private static void resolveRelativePremiumDatabase(Map<String, Object> root, Path dataDirectory) {
        if (!bool(root, "premium.enabled", false)) return;
        if (!"SQLITE".equalsIgnoreCase(string(root, "premium.database.backend", ""))) return;
        String raw = string(root, "premium.database.database", "");
        if (raw.isBlank()) return;
        Path path = Path.of(raw);
        if (!path.isAbsolute()) root.put("premium.database.database", dataDirectory.resolve(path).normalize().toString());
    }

    private static String boundedMessage(String message) {
        if (message == null || message.isBlank()) return "Authentication required.";
        return message.length() > 512 ? message.substring(0, 512) : message;
    }

    private static String requireSecret(String secret) {
        if (secret == null || secret.isBlank() || secret.length() < MIN_SECRET_LENGTH
            || secret.length() > MAX_SECRET_LENGTH) {
            throw new IllegalArgumentException("A proxy shared secret between 16 and 256 characters is required");
        }
        return secret;
    }

    private static String loadOrCreateSecret(Path dataDirectory) throws IOException {
        Path secretFile = dataDirectory.resolve("proxySharedSecret.txt");
        if (Files.exists(secretFile, LinkOption.NOFOLLOW_LINKS)) {
            SecureFileAccess.harden(secretFile);
            String existing;
            try (InputStream input = Files.newInputStream(secretFile, LinkOption.NOFOLLOW_LINKS)) {
                existing = new String(input.readAllBytes(), StandardCharsets.UTF_8).trim();
            }
            if (!existing.isBlank() && existing.length() <= MAX_SECRET_LENGTH) return existing;
            throw new IOException("proxySharedSecret.txt is invalid");
        }
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        String generated = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        try (OutputStream output = SecureFileAccess.createNewPrivateFile(secretFile)) {
            output.write((generated + System.lineSeparator()).getBytes(StandardCharsets.UTF_8));
        }
        return generated;
    }

    private static String defaultConfig() {
        return "# AuthMe native proxy bridge\n"
            + "authServers: [lobby]\n"
            + "allServersAreAuthServers: false\n"
            + "backendCredentials:\n"
            + "  lobby:\n"
            + "    backendId: backend\n"
            + "    # Blank uses proxySharedSecret for this single backend only.\n"
            + "    secret: ''\n"
            + "serverSwitch:\n"
            + "  requiresAuth: true\n"
            + "  kickMessage: 'Authentication required.'\n"
            + "autoLogin: true\n"
            + "sendOnLogout: false\n"
            + "unloggedUserServer: ''\n"
            + "commands:\n"
            + "  requireAuth: true\n"
            + "  whitelist: [/login, /register, /l, /reg, /email, /captcha, /2fa, /totp, /log]\n"
            + "chatRequiresAuth: true\n"
            + "loginServer: ''\n"
            + "# If blank, use the generated value in proxySharedSecret.txt.\n"
            + "proxySharedSecret: ''\n"
            + "premium:\n"
            + "  enabled: false\n"
            + "  keepOfflineUuidCompatibility: false\n"
            + "  lookupFailureMessage: 'Premium account verification is temporarily unavailable.'\n"
            + "  # When enabled, use the same AuthMe schema with a SELECT-only database account.\n"
            + "  database:\n"
            + "    backend: SQLITE\n"
            + "    database: authme.db\n"
            + "    host: 127.0.0.1\n"
            + "    port: '3306'\n"
            + "    user: ''\n"
            + "    password: ''\n"
            + "    table: authme\n"
            + "    tlsMode: VERIFY_IDENTITY\n"
            + "    columns:\n"
            + "      username: username\n"
            + "      premiumUuid: premiumUUID\n";
    }
}
