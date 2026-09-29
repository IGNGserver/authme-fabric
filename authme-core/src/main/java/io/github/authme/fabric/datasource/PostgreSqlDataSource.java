package io.github.authme.fabric.datasource;

import io.github.authme.fabric.util.Log;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * PostgreSQL data source. Stores the same logical record set as AuthMe's MySQL backend, with
 * PostgreSQL-appropriate column types so a database admin can read/write the same data with
 * standard SQL tooling. (Account hashes and column names are identical across backends, so
 * passwords computed by an AuthMe Spigot/MySQL install work verbatim here.)
 *
 * <p>Type mappings vs. MySQL:
 * <ul>
 *   <li>{@code MEDIUMINT UNSIGNED AUTO_INCREMENT} → {@code SERIAL} (integer + sequence)</li>
 *   <li>{@code DOUBLE} → {@code DOUBLE PRECISION}</li>
 *   <li>{@code FLOAT} → {@code REAL}</li>
 *   <li>{@code SMALLINT} (isLogged / hasSession) → {@code SMALLINT}</li>
 *   <li>{@code VARCHAR} stays; the password column uses {@code COLLATE "C"} so hash comparison is
 *       case-/byte-sensitive like AuthMe's {@code ascii_bin}.</li>
 * </ul>
 */
public class PostgreSqlDataSource extends AbstractSqlDataSource {

    public PostgreSqlDataSource(DbSettings settings) throws SQLException {
        super(settings);
    }

    /** Opens an existing schema without issuing DDL. Use a SELECT-only database principal. */
    public PostgreSqlDataSource(DbSettings settings, boolean readOnly) throws SQLException {
        super(settings, !readOnly, null, !readOnly);
    }

    @Override
    protected String driverClassName() {
        return "org.postgresql.Driver";
    }

    @Override
    public DataSourceType getType() {
        return DataSourceType.POSTGRESQL;
    }

    @Override
    protected String buildJdbcUrl() {
        StringBuilder u = new StringBuilder("jdbc:postgresql://")
            .append(settings.host).append(':').append(settings.port).append('/').append(settings.database);
        u.append("?binaryTransfer=true&sslmode=").append(postgresSslMode(settings.tlsMode));
        return u.toString();
    }

    private static String postgresSslMode(DbSettings.TlsMode mode) {
        return switch (mode) {
            case DISABLED -> "disable";
            case REQUIRED -> "require";
            case VERIFY_CA -> "verify-ca";
            case VERIFY_IDENTITY -> "verify-full";
        };
    }

    @Override
    protected boolean isColumnMissing(DatabaseMetaData md, String columnName) throws SQLException {
        // PostgreSQL stores table names lowercase when unquoted; our configured name may be mixed-case.
        // Try both before declaring the column missing.
        try (ResultSet rs = md.getColumns(null, null, settings.table, columnName)) {
            if (rs.next()) return false;
        }
        try (ResultSet rs = md.getColumns(null, null, settings.table.toLowerCase(java.util.Locale.ROOT), columnName)) {
            return !rs.next();
        }
    }

    @Override
    protected String quote(String identifier) {
        return '"' + identifier.replace("\"", "\"\"") + '"';
    }

    @Override
    protected void createSchemaAndColumns() throws SQLException {
        Connection con = null;
        try {
            con = borrowConnection();
            try (Statement st = con.createStatement()) {
            String t = quote(settings.table);
            // Ensure a sequence-backed id exists; CREATE TABLE IF NOT EXISTS won't duplicate.
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + t + " ("
                + quote(col.ID) + " SERIAL PRIMARY KEY);");

            DatabaseMetaData md = con.getMetaData();

            if (isColumnMissing(md, col.NAME)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.NAME)
                    + " VARCHAR(255) NOT NULL UNIQUE;");
            }
            if (isColumnMissing(md, col.REAL_NAME)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.REAL_NAME)
                    + " VARCHAR(255) NOT NULL DEFAULT '';");
            }
            if (isColumnMissing(md, col.PASSWORD)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.PASSWORD)
                    + " VARCHAR(255) COLLATE \"C\" NOT NULL;");
            }
            if (col.hasSaltColumn() && isColumnMissing(md, col.SALT)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.SALT) + " VARCHAR(255);");
            }
            if (isColumnMissing(md, col.LAST_IP)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.LAST_IP)
                    + " VARCHAR(40) COLLATE \"C\";");
            }
            if (isColumnMissing(md, col.LAST_LOGIN)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.LAST_LOGIN) + " BIGINT;");
            }
            if (isColumnMissing(md, col.REGISTRATION_DATE)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.REGISTRATION_DATE)
                    + " BIGINT NOT NULL DEFAULT 0;");
            }
            if (isColumnMissing(md, col.REGISTRATION_IP)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.REGISTRATION_IP)
                    + " VARCHAR(40) COLLATE \"C\";");
            }
            if (isColumnMissing(md, col.LASTLOC_X)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN "
                    + quote(col.LASTLOC_X) + " DOUBLE PRECISION NOT NULL DEFAULT 0.0, "
                    + quote(col.LASTLOC_Y) + " DOUBLE PRECISION NOT NULL DEFAULT 0.0, "
                    + quote(col.LASTLOC_Z) + " DOUBLE PRECISION NOT NULL DEFAULT 0.0;");
            }
            if (isColumnMissing(md, col.LASTLOC_WORLD)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.LASTLOC_WORLD)
                    + " VARCHAR(255) NOT NULL DEFAULT 'minecraft:overworld';");
            }
            if (isColumnMissing(md, col.LASTLOC_YAW)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.LASTLOC_YAW) + " REAL;");
            }
            if (isColumnMissing(md, col.LASTLOC_PITCH)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.LASTLOC_PITCH) + " REAL;");
            }
            if (isColumnMissing(md, col.EMAIL)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.EMAIL) + " VARCHAR(255);");
            }
            if (isColumnMissing(md, col.IS_LOGGED)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.IS_LOGGED)
                    + " SMALLINT NOT NULL DEFAULT 0;");
            }
            if (isColumnMissing(md, col.HAS_SESSION)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.HAS_SESSION)
                    + " SMALLINT NOT NULL DEFAULT 0;");
            }
            if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty() && isColumnMissing(md, col.TOTP_KEY)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.TOTP_KEY) + " VARCHAR(32);");
            }
            if (col.hasPlayerUuidColumn() && isColumnMissing(md, col.PLAYER_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.PLAYER_UUID) + " VARCHAR(36);");
            }
            if (col.hasPremiumUuidColumn() && isColumnMissing(md, col.PREMIUM_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + quote(col.PREMIUM_UUID) + " VARCHAR(36);");
            }
            }
        } finally {
            releaseConnection(con);
        }
        Log.info("PostgreSQL setup finished (table=" + settings.table + ")");
    }
}
