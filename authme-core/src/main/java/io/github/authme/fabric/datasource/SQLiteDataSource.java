package io.github.authme.fabric.datasource;

import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.SecureFileAccess;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;

/**
 * SQLite data source. Creates the AuthMe-shaped SQLite table on first run. Because Fabric servers
 * (unlike Bukkit) do not ship an SQLite driver, the xerial {@code sqlite-jdbc} driver is bundled
 * inside this mod via Fabric Loader's jar-in-jar feature.
 *
 * <p>{@code settings.database} is expected to hold the absolute path to the {@code .db} file for
 * SQLite (resolved by the configuration layer).
 */
public class SQLiteDataSource extends AbstractSqlDataSource {

    private final boolean readOnly;

    public SQLiteDataSource(DbSettings settings) throws SQLException {
        this(settings, false);
    }

    /** Opens an existing SQLite file without schema creation or write access. */
    public SQLiteDataSource(DbSettings settings, boolean readOnly) throws SQLException {
        super(prepareSettings(settings, readOnly), !readOnly,
            readOnly ? readOnlyJdbcUrl(settings) : null, !readOnly);
        this.readOnly = readOnly;
        try {
            SecureFileAccess.harden(Path.of(settings.database).toAbsolutePath().normalize());
        } catch (IOException | RuntimeException e) {
            close();
            throw new SQLException("Could not restrict SQLite database permissions", e);
        }
    }

    @Override
    public void reload() {
        if (readOnly) {
            Log.warn("Ignoring reload on a read-only SQLite data source");
            return;
        }
        super.reload();
    }

    private static String readOnlyJdbcUrl(DbSettings settings) throws SQLException {
        try {
            Path path = Path.of(settings.database).toAbsolutePath().normalize();
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                throw new SQLException("Read-only SQLite source does not exist: " + path);
            }
            return "jdbc:sqlite:file:" + path.toString().replace('\\', '/') + "?mode=ro";
        } catch (java.nio.file.InvalidPathException e) {
            throw new SQLException("Invalid read-only SQLite source path", e);
        }
    }

    private static DbSettings prepareSettings(DbSettings settings, boolean readOnly) throws SQLException {
        if (settings == null || settings.database == null || settings.database.isBlank()) {
            throw new SQLException("SQLite database path is missing");
        }
        try {
            Path path = Path.of(settings.database).toAbsolutePath().normalize();
            Path parent = path.getParent();
            if (parent != null) Files.createDirectories(parent);
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                SecureFileAccess.harden(path);
                if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                    throw new SQLException("SQLite database path is not a regular file: " + path);
                }
            } else if (readOnly) {
                throw new SQLException("Read-only SQLite source does not exist: " + path);
            } else {
                // Create the database file privately before the JDBC driver opens it. Otherwise
                // a permissive umask can expose a newly created database during schema setup.
                try (OutputStream ignored = SecureFileAccess.createNewPrivateFile(path)) {
                    // The SQLite driver will initialise this empty file on its first connection.
                }
            }
            return settings;
        } catch (IOException | RuntimeException e) {
            throw new SQLException("Could not prepare SQLite database path", e);
        }
    }

    @Override
    protected String driverClassName() {
        return "org.sqlite.JDBC";
    }

    @Override
    public DataSourceType getType() {
        return DataSourceType.SQLITE;
    }

    @Override
    protected String buildJdbcUrl() {
        return "jdbc:sqlite:" + settings.database;
    }

    @Override
    protected boolean isColumnMissing(DatabaseMetaData md, String columnName) throws SQLException {
        // SQLite's catalog/scheme must be null (passing the file path yields no matches).
        try (ResultSet rs = md.getColumns(null, null, settings.table, columnName)) {
            return !rs.next();
        }
    }

    @Override
    protected void createSchemaAndColumns() throws SQLException {
        String t = settings.table;
        StringBuilder sb = new StringBuilder("CREATE TABLE IF NOT EXISTS " + t + " (");
        sb.append(col.ID).append(" INTEGER PRIMARY KEY AUTOINCREMENT, ");
        sb.append(col.NAME).append(" VARCHAR(255) NOT NULL UNIQUE, ");
        sb.append(col.REAL_NAME).append(" VARCHAR(255) NOT NULL, ");
        sb.append(col.PASSWORD).append(" VARCHAR(255) NOT NULL, ");
        if (col.hasSaltColumn()) sb.append(col.SALT).append(" VARCHAR(255), ");
        sb.append(col.LAST_IP).append(" VARCHAR(40), ");
        sb.append(col.LAST_LOGIN).append(" INTEGER, ");
        sb.append(col.REGISTRATION_DATE).append(" BIGINT NOT NULL DEFAULT 0, ");
        sb.append(col.REGISTRATION_IP).append(" VARCHAR(40), ");
        sb.append(col.LASTLOC_X).append(" DOUBLE NOT NULL DEFAULT 0.0, ");
        sb.append(col.LASTLOC_Y).append(" DOUBLE NOT NULL DEFAULT 0.0, ");
        sb.append(col.LASTLOC_Z).append(" DOUBLE NOT NULL DEFAULT 0.0, ");
        sb.append(col.LASTLOC_WORLD).append(" VARCHAR(255) NOT NULL DEFAULT 'world', ");
        sb.append(col.LASTLOC_YAW).append(" FLOAT, ");
        sb.append(col.LASTLOC_PITCH).append(" FLOAT, ");
        sb.append(col.EMAIL).append(" VARCHAR(255), ");
        sb.append(col.IS_LOGGED).append(" INTEGER NOT NULL DEFAULT 0, ");
        sb.append(col.HAS_SESSION).append(" INTEGER NOT NULL DEFAULT 0, ");
        if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) sb.append(col.TOTP_KEY).append(" VARCHAR(32), ");
        if (col.hasPremiumUuidColumn()) sb.append(col.PREMIUM_UUID).append(" VARCHAR(36), ");
        if (col.hasPlayerUuidColumn()) sb.append(col.PLAYER_UUID).append(" VARCHAR(36), ");
        // strip trailing ", "
        String sql = sb.substring(0, sb.length() - 2) + ");";

        Connection con = null;
        try {
            con = borrowConnection();
            try (Statement st = con.createStatement()) {
            st.executeUpdate(sql);
            DatabaseMetaData md = con.getMetaData();
            if (col.hasSaltColumn() && isColumnMissing(md, col.SALT)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.SALT + " VARCHAR(255);");
            }
            if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty() && isColumnMissing(md, col.TOTP_KEY)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.TOTP_KEY + " VARCHAR(32);");
            }
            if (col.hasPremiumUuidColumn() && isColumnMissing(md, col.PREMIUM_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.PREMIUM_UUID + " VARCHAR(36);");
            }
            if (col.hasPlayerUuidColumn() && isColumnMissing(md, col.PLAYER_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.PLAYER_UUID + " VARCHAR(36);");
            }
            }
        } finally {
            releaseConnection(con);
        }
        Log.info("SQLite setup finished (file=" + settings.database + ")");
    }
}
