package io.github.authme.fabric.datasource;

import io.github.authme.fabric.util.Log;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * MySQL data source implementing the identical table schema AuthMe produces (configurable column
 * names). On startup it creates the table and any missing columns, so a brand-new database will be
 * shaped exactly like an AuthMe one, and an existing AuthMe database will not be altered.
 *
 * <p>This guarantees that a Fabric server running this mod and a Bukkit/Spigot server running the
 * original AuthMe can point at the <em>same</em> database and share accounts.
 */
public class MySQLDataSource extends AbstractSqlDataSource {

    public MySQLDataSource(DbSettings settings) throws SQLException {
        super(settings);
    }

    @Override
    protected String driverClassName() {
        return "com.mysql.cj.jdbc.Driver";
    }

    @Override
    public DataSourceType getType() {
        return DataSourceType.MYSQL;
    }

    @Override
    protected String buildJdbcUrl() {
        String sslMode = !settings.useSsl ? "DISABLED"
            : (!settings.checkServerCertificate ? "PREFERRED" : "VERIFY_CA");
        StringBuilder u = new StringBuilder("jdbc:mysql://")
            .append(settings.host).append(':').append(settings.port).append('/').append(settings.database);
        u.append("?useUnicode=true&characterEncoding=utf8&sslMode=").append(sslMode);
        if (settings.allowPublicKeyRetrieval) {
            u.append("&allowPublicKeyRetrieval=true");
        }
        u.append("&rewriteBatchedStatements=true&serverTimezone=UTC&socketTimeout=600000&autoReconnect=true");
        return u.toString();
    }

    @Override
    protected void createSchemaAndColumns() throws SQLException {
        String t = settings.table;
        try (Connection con = borrowConnection(); Statement st = con.createStatement()) {
            st.executeUpdate("CREATE TABLE IF NOT EXISTS " + t + " ("
                + col.ID + " MEDIUMINT(8) UNSIGNED AUTO_INCREMENT, PRIMARY KEY (" + col.ID + ")"
                + ") CHARACTER SET = utf8;");

            DatabaseMetaData md = con.getMetaData();
            if (isColumnMissing(md, col.NAME)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.NAME
                    + " VARCHAR(255) NOT NULL UNIQUE AFTER " + col.ID + ";");
            }
            if (isColumnMissing(md, col.REAL_NAME)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.REAL_NAME
                    + " VARCHAR(255) NOT NULL AFTER " + col.NAME + ";");
            }
            if (isColumnMissing(md, col.PASSWORD)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.PASSWORD
                    + " VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL;");
            }
            if (col.hasSaltColumn() && isColumnMissing(md, col.SALT)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.SALT + " VARCHAR(255);");
            }
            if (isColumnMissing(md, col.LAST_IP)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.LAST_IP
                    + " VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin;");
            }
            if (isColumnMissing(md, col.LAST_LOGIN)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.LAST_LOGIN + " BIGINT;");
            }
            if (isColumnMissing(md, col.REGISTRATION_DATE)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.REGISTRATION_DATE
                    + " BIGINT NOT NULL DEFAULT 0;");
            }
            if (isColumnMissing(md, col.REGISTRATION_IP)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.REGISTRATION_IP
                    + " VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin;");
            }
            if (isColumnMissing(md, col.LASTLOC_X)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN "
                    + col.LASTLOC_X + " DOUBLE NOT NULL DEFAULT '0.0' AFTER " + col.LAST_LOGIN
                    + " , ADD " + col.LASTLOC_Y + " DOUBLE NOT NULL DEFAULT '0.0' AFTER " + col.LASTLOC_X
                    + " , ADD " + col.LASTLOC_Z + " DOUBLE NOT NULL DEFAULT '0.0' AFTER " + col.LASTLOC_Y + ";");
            }
            if (isColumnMissing(md, col.LASTLOC_WORLD)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.LASTLOC_WORLD
                    + " VARCHAR(255) NOT NULL DEFAULT 'world' AFTER " + col.LASTLOC_Z + ";");
            }
            if (isColumnMissing(md, col.LASTLOC_YAW)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.LASTLOC_YAW + " FLOAT;");
            }
            if (isColumnMissing(md, col.LASTLOC_PITCH)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.LASTLOC_PITCH + " FLOAT;");
            }
            if (isColumnMissing(md, col.EMAIL)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.EMAIL + " VARCHAR(255);");
            }
            if (isColumnMissing(md, col.IS_LOGGED)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.IS_LOGGED
                    + " SMALLINT NOT NULL DEFAULT '0' AFTER " + col.EMAIL + ";");
            }
            if (isColumnMissing(md, col.HAS_SESSION)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.HAS_SESSION
                    + " SMALLINT NOT NULL DEFAULT '0' AFTER " + col.IS_LOGGED + ";");
            }
            if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty() && isColumnMissing(md, col.TOTP_KEY)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.TOTP_KEY + " VARCHAR(32);");
            }
            if (col.hasPlayerUuidColumn() && isColumnMissing(md, col.PLAYER_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.PLAYER_UUID + " VARCHAR(36);");
            }
            if (col.hasPremiumUuidColumn() && isColumnMissing(md, col.PREMIUM_UUID)) {
                st.executeUpdate("ALTER TABLE " + t + " ADD COLUMN " + col.PREMIUM_UUID + " VARCHAR(36);");
            }
        }
        Log.info("MySQL setup finished (table=" + t + ")");
    }
}