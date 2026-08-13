package io.github.authme.fabric.datasource;

import io.github.authme.fabric.util.Log;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * SQLite data source. Creates the AuthMe-shaped SQLite table on first run. Because Fabric servers
 * (unlike Bukkit) do not ship an SQLite driver, the xerial {@code sqlite-jdbc} driver is bundled
 * inside this mod via Fabric Loader's jar-in-jar feature.
 *
 * <p>{@code settings.database} is expected to hold the absolute path to the {@code .db} file for
 * SQLite (resolved by the configuration layer).
 */
public class SQLiteDataSource extends AbstractSqlDataSource {

    public SQLiteDataSource(DbSettings settings) throws SQLException {
        super(settings);
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

        try (Connection con = borrowConnection(); Statement st = con.createStatement()) {
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
        Log.info("SQLite setup finished (file=" + settings.database + ")");
    }
}