package io.github.authme.fabric.converter;

import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.security.HashedPassword;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Imports the common SQLite/YAML layouts used by AuthPlus, LibreLogin, LimboAuth, nLogin,
 * OpeNLogin, tiAuth and NexAuth. The reader is metadata-driven so minor schema revisions do not
 * turn a converter into a silent no-op; every row is either imported, skipped with a reason, or
 * causes a visible conversion error.
 */
public class PluginImportConverter implements Converter {

    protected final String id;
    protected final String description;
    protected final String defaultPath;
    protected final String defaultTable;
    protected final boolean yaml;

    public PluginImportConverter(String id, String description, String defaultPath, String defaultTable) {
        this(id, description, defaultPath, defaultTable, false);
    }

    public PluginImportConverter(String id, String description, String defaultPath, String defaultTable, boolean yaml) {
        this.id = id;
        this.description = description;
        this.defaultPath = defaultPath;
        this.defaultTable = defaultTable;
        this.yaml = yaml;
    }

    @Override public String id() { return id; }
    @Override public String description() { return description; }

    @Override
    public Result convert(DataSource target) throws Exception {
        String argument = argumentOrDefault(null);
        if (yaml) return importYaml(target, Path.of(argument));
        if (target == null) throw new IllegalArgumentException("No target data source is available");
        Path source = Path.of(argument.contains("|") ? argument.substring(0, argument.indexOf('|')).trim() : argument);
        String table = defaultTable;
        int separator = argument.indexOf('|');
        if (separator >= 0) {
            table = validateIdentifier(argument.substring(separator + 1).trim(), "table");
        }
        if (!Files.isRegularFile(source)) {
            throw new IOException("Source database does not exist: " + source.toAbsolutePath());
        }
        Class.forName("org.sqlite.JDBC");
        try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + source.toAbsolutePath());
             Statement statement = connection.createStatement();
             ResultSet rows = statement.executeQuery("SELECT * FROM " + quoteIdentifier(table))) {
            return importRows(target, rows);
        }
    }

    /** Called by the registry after it has inserted the command argument into this instance. */
    public PluginImportConverter withArgument(String argument) {
        return new WithArgument(this, argument);
    }

    protected String argumentOrDefault(String argument) {
        return argument == null || argument.isBlank() ? defaultPath : argument.trim();
    }

    protected Result importRows(DataSource target, ResultSet rows) throws SQLException {
        ResultSetMetaData metadata = rows.getMetaData();
        Map<String, Integer> columns = columns(metadata);
        String nameColumn = first(columns, "last_name", "last_nickname", "realname", "real_name",
            "username", "user", "name", "player", "nickname");
        String hashColumn = first(columns, "password", "hashed_password", "hash", "pass", "passwd");
        if (nameColumn == null || hashColumn == null) {
            throw new SQLException("Source table has no recognizable account name/password columns");
        }
        String saltColumn = first(columns, "salt", "password_salt", "pass_salt");
        String realNameColumn = first(columns, "realname", "real_name", "last_name", "last_nickname", "name", "username");
        String ipColumn = first(columns, "last_ip", "ip", "address", "lastip");
        String emailColumn = first(columns, "email", "mail");
        String regColumn = first(columns, "creation_date", "regdate", "reg_date", "joined", "registration_date");
        String lastColumn = first(columns, "last_seen", "lastlogin", "last_login", "last_login_time");
        String uuidColumn = first(columns, "unique_id", "uuid", "player_uuid");
        String premiumColumn = first(columns, "premium_uuid", "premiumuuid");
        String totpColumn = first(columns, "secret", "totp", "totp_key");
        String loggedColumn = first(columns, "islogged", "is_logged", "logged");
        String sessionColumn = first(columns, "hassession", "has_session", "session");
        int imported = 0;
        int skipped = 0;
        while (rows.next()) {
            String realName = string(rows, realNameColumn == null ? nameColumn : realNameColumn);
            if (realName == null || realName.isBlank()) { skipped++; continue; }
            String name = realName.toLowerCase(Locale.ROOT);
            String hash = string(rows, hashColumn);
            if (hash == null || hash.isBlank()) { skipped++; continue; }
            DataSource.CheckResult exists = target.checkAuthAvailable(name);
            if (!exists.successful()) throw new SQLException("Target database became unavailable while importing");
            if (exists.available()) { skipped++; continue; }
            PlayerAuth account = PlayerAuth.builder()
                .name(name)
                .realName(realName)
                .password(hash, string(rows, saltColumn))
                .locWorld(string(rows, first(columns, "world", "last_world", "lastlocworld")) == null
                    ? "world" : string(rows, first(columns, "world", "last_world", "lastlocworld")))
                .lastIp(string(rows, ipColumn))
                .email(string(rows, emailColumn))
                .registrationDate(longValue(rows, regColumn))
                .lastLogin(nullableLong(rows, lastColumn))
                .uuid(parseUuid(string(rows, uuidColumn)))
                .premiumUuid(parseUuid(string(rows, premiumColumn)))
                .totpKey(string(rows, totpColumn))
                .logged(booleanValue(rows, loggedColumn))
                .hasSession(booleanValue(rows, sessionColumn))
                .build();
            if (target.saveAuth(account)) imported++; else skipped++;
        }
        return new Result(imported, skipped, "source=" + id);
    }

    protected Result importYaml(DataSource target, Path file) throws IOException {
        if (!Files.isRegularFile(file)) throw new IOException("Source YAML does not exist: " + file.toAbsolutePath());
        int imported = 0;
        int skipped = 0;
        try (InputStream input = Files.newInputStream(file)) {
            Object loaded = new Yaml(new SafeConstructor(new LoaderOptions())).load(input);
            if (!(loaded instanceof Map<?, ?> root)) throw new IOException("AuthPlus YAML root is not a map");
            for (Map.Entry<?, ?> entry : root.entrySet()) {
                if (!(entry.getValue() instanceof Map<?, ?> values)) { skipped++; continue; }
                String name = text(values, "name", "username", "player");
                String uuidText = String.valueOf(entry.getKey());
                UUID uuid = parseUuid(uuidText);
                if ((name == null || name.isBlank()) && uuid != null) name = text(values, "lastName", "last_name");
                if (name == null || name.isBlank()) { skipped++; continue; }
                String hash = text(values, "hash", "password", "passwordHash");
                if (hash == null || hash.isBlank()) { skipped++; continue; }
                name = name.toLowerCase(Locale.ROOT);
                DataSource.CheckResult exists = target.checkAuthAvailable(name);
                if (!exists.successful()) throw new IOException("Target database became unavailable while importing");
                if (exists.available()) { skipped++; continue; }
                PlayerAuth account = PlayerAuth.builder().name(name).realName(name)
                    .password(hash, text(values, "salt"))
                    .locWorld(text(values, "world", "last_world") == null ? "world"
                        : text(values, "world", "last_world"))
                    .uuid(uuid)
                    .email(text(values, "email"))
                    .build();
                if (target.saveAuth(account)) imported++; else skipped++;
            }
        }
        return new Result(imported, skipped, "source=" + id);
    }

    private static Map<String, Integer> columns(ResultSetMetaData metadata) throws SQLException {
        Map<String, Integer> result = new LinkedHashMap<>();
        for (int i = 1; i <= metadata.getColumnCount(); i++) {
            result.put(metadata.getColumnLabel(i).toLowerCase(Locale.ROOT), i);
            result.putIfAbsent(metadata.getColumnName(i).toLowerCase(Locale.ROOT), i);
        }
        return result;
    }

    private static String first(Map<String, Integer> columns, String... names) {
        for (String name : names) if (columns.containsKey(name)) return name;
        return null;
    }

    private static String string(ResultSet rows, String column) throws SQLException {
        return column == null ? null : rows.getString(column);
    }

    private static long longValue(ResultSet rows, String column) throws SQLException {
        Long value = nullableLong(rows, column);
        return value == null ? 0L : value;
    }

    private static Long nullableLong(ResultSet rows, String column) throws SQLException {
        if (column == null) return null;
        Object value = rows.getObject(column);
        if (value == null) return null;
        if (value instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(value)); } catch (NumberFormatException e) { return null; }
    }

    private static boolean booleanValue(ResultSet rows, String column) throws SQLException {
        if (column == null) return false;
        Object value = rows.getObject(column);
        if (value instanceof Boolean b) return b;
        if (value instanceof Number n) return n.intValue() != 0;
        return "true".equalsIgnoreCase(String.valueOf(value)) || "1".equals(String.valueOf(value));
    }

    private static String text(Map<?, ?> values, String... keys) {
        for (String key : keys) {
            for (Map.Entry<?, ?> entry : values.entrySet()) {
                if (String.valueOf(entry.getKey()).equalsIgnoreCase(key) && entry.getValue() != null) {
                    return String.valueOf(entry.getValue());
                }
            }
        }
        return null;
    }

    private static UUID parseUuid(String value) {
        if (value == null || value.isBlank()) return null;
        String normalized = value.trim();
        if (normalized.length() == 32 && normalized.indexOf('-') < 0) {
            normalized = normalized.substring(0, 8) + "-" + normalized.substring(8, 12) + "-"
                + normalized.substring(12, 16) + "-" + normalized.substring(16, 20) + "-" + normalized.substring(20);
        }
        try { return UUID.fromString(normalized); } catch (IllegalArgumentException e) { return null; }
    }

    private static String validateIdentifier(String value, String label) {
        if (value == null || !value.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid " + label + " identifier");
        }
        return value;
    }

    private static String quoteIdentifier(String value) {
        return "\"" + validateIdentifier(value, "table").replace("\"", "\"\"") + "\"";
    }

    /**
     * A small immutable wrapper used by the registry to bind the free-form command argument.
     */
    private static final class WithArgument extends PluginImportConverter {
        private final String argument;

        private WithArgument(PluginImportConverter base, String argument) {
            super(base.id, base.description, base.defaultPath, base.defaultTable, base.yaml);
            this.argument = argument;
        }

        @Override
        public Result convert(DataSource target) throws Exception {
            if (yaml) return importYaml(target, Path.of(argumentOrDefault(argument)));
            String sourceArgument = argumentOrDefault(argument);
            Path source = Path.of(sourceArgument.contains("|") ? sourceArgument.substring(0, sourceArgument.indexOf('|')) : sourceArgument);
            String table = defaultTable;
            int separator = sourceArgument.indexOf('|');
            if (separator >= 0) table = validateIdentifier(sourceArgument.substring(separator + 1).trim(), "table");
            if (!Files.isRegularFile(source)) throw new IOException("Source database does not exist: " + source.toAbsolutePath());
            Class.forName("org.sqlite.JDBC");
            try (Connection connection = DriverManager.getConnection("jdbc:sqlite:" + source.toAbsolutePath());
                 Statement statement = connection.createStatement();
                 ResultSet rows = statement.executeQuery("SELECT * FROM " + quoteIdentifier(table))) {
                return importRows(target, rows);
            }
        }
    }
}
