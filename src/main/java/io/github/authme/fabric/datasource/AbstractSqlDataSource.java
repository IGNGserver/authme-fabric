package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.util.Log;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;

/**
 * Shared SQL implementation for the MySQL, MariaDB and SQLite backends. All account CRUD uses plain,
 * portable SQL built from the configured {@link Columns} so a database shared with the original
 * AuthMe plugin is read and written identically. Backend-specific DDL lives in the concrete
 * subclasses.
 */
public abstract class AbstractSqlDataSource implements DataSource {

    protected final DbSettings settings;
    protected final Columns col;
    protected SimpleConnectionPool pool;

    protected AbstractSqlDataSource(DbSettings settings) throws SQLException {
        this.settings = settings;
        this.col = settings.columns;
        initDriver();
        initPool();
        try {
            createSchemaAndColumns();
        } catch (SQLException e) {
            pool.close();
            throw e;
        }
        Log.info(getType() + " data source initialised (table=" + settings.table + ")");
    }

    private void initDriver() throws SQLException {
        try {
            Class.forName(driverClassName());
        } catch (ClassNotFoundException e) {
            throw new SQLException("Database driver not available on the classpath: " + driverClassName(), e);
        }
    }

    private void initPool() {
        this.pool = new SimpleConnectionPool(buildJdbcUrl(), jdbcProps(), Math.max(2, settings.poolSize));
    }

    protected Properties jdbcProps() {
        Properties p = new Properties();
        if (settings.user != null && !settings.user.isEmpty()) {
            p.setProperty("user", settings.user);
        }
        if (settings.password != null) {
            p.setProperty("password", settings.password);
        }
        return p;
    }

    protected abstract String driverClassName();

    protected abstract String buildJdbcUrl();

    public abstract DataSourceType getType();

    protected abstract void createSchemaAndColumns() throws SQLException;

    protected Connection borrowConnection() throws SQLException {
        return pool.borrow(30_000L);
    }

    protected void releaseConnection(Connection c) {
        pool.release(c);
    }

    @Override
    public Columns getColumns() {
        return col;
    }

    // ---------------------------------------------------------------- CRUD

    @Override
    public PlayerAuth getAuth(String user) {
        String sql = "SELECT * FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    if (rs.next()) {
                        return buildAuthFromResultSet(rs);
                    }
                }
            }
        } catch (SQLException e) {
            Log.error("Could not fetch auth for " + user, e);
        } finally {
            releaseConnection(c);
        }
        return null;
    }

    @Override
    public boolean isAuthAvailable(String user) {
        String sql = "SELECT 1 FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    return rs.next();
                }
            }
        } catch (SQLException e) {
            Log.error("Could not check auth availability for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean saveAuth(PlayerAuth auth) {
        String[] cols = composeInsertColumns();
        StringBuilder sql = new StringBuilder("INSERT INTO ").append(quote(settings.table)).append(" (");
        StringBuilder ph = new StringBuilder();
        for (int i = 0; i < cols.length; i++) {
            if (i > 0) { sql.append(", "); ph.append(", "); }
            sql.append(quote(cols[i]));
            ph.append("?");
        }
        sql.append(") VALUES (").append(ph).append(");");

        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql.toString())) {
                int idx = 1;
                pst.setString(idx++, auth.getName() == null ? null : auth.getName().toLowerCase(Locale.ROOT));
                pst.setString(idx++, auth.getRealName());
                pst.setString(idx++, auth.getHash());
                if (col.hasSaltColumn()) {
                    pst.setString(idx++, auth.getSalt());
                }
                pst.setString(idx++, auth.getLastIp());
                setNullableLong(pst, idx++, auth.getLastLogin());
                pst.setLong(idx++, auth.getRegistrationDate());
                pst.setString(idx++, auth.getRegistrationIp());
                pst.setDouble(idx++, auth.getLocX());
                pst.setDouble(idx++, auth.getLocY());
                pst.setDouble(idx++, auth.getLocZ());
                pst.setString(idx++, auth.getLocWorld());
                pst.setFloat(idx++, auth.getLocYaw());
                pst.setFloat(idx++, auth.getLocPitch());
                pst.setString(idx++, auth.getEmail());
                pst.setInt(idx++, auth.isLogged() ? 1 : 0);
                pst.setInt(idx++, auth.hasSession() ? 1 : 0);
                if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) {
                    pst.setString(idx++, auth.getTotpKey());
                }
                if (col.hasPremiumUuidColumn()) {
                    pst.setString(idx++, auth.getPremiumUuid() == null ? null : auth.getPremiumUuid().toString());
                }
                if (col.hasPlayerUuidColumn()) {
                    pst.setString(idx++, auth.getUuid() == null ? null : auth.getUuid().toString());
                }
                pst.executeUpdate();
                return true;
            }
        } catch (SQLException e) {
            Log.error("Could not save auth for " + auth.getName(), e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    private String[] composeInsertColumns() {
        List<String> l = new ArrayList<>();
        l.add(col.NAME);
        l.add(col.REAL_NAME);
        l.add(col.PASSWORD);
        if (col.hasSaltColumn()) l.add(col.SALT);
        l.add(col.LAST_IP);
        l.add(col.LAST_LOGIN);
        l.add(col.REGISTRATION_DATE);
        l.add(col.REGISTRATION_IP);
        l.add(col.LASTLOC_X);
        l.add(col.LASTLOC_Y);
        l.add(col.LASTLOC_Z);
        l.add(col.LASTLOC_WORLD);
        l.add(col.LASTLOC_YAW);
        l.add(col.LASTLOC_PITCH);
        l.add(col.EMAIL);
        l.add(col.IS_LOGGED);
        l.add(col.HAS_SESSION);
        if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) l.add(col.TOTP_KEY);
        if (col.hasPremiumUuidColumn()) l.add(col.PREMIUM_UUID);
        if (col.hasPlayerUuidColumn()) l.add(col.PLAYER_UUID);
        return l.toArray(new String[0]);
    }

    @Override
    public boolean updatePassword(String user, HashedPassword password) {
        boolean separateSalt = col.hasSaltColumn() && password.getSalt() != null;
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.PASSWORD) + "=?"
            + (separateSalt ? ", " + quote(col.SALT) + "=?" : "")
            + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                int idx = 1;
                pst.setString(idx++, password.getHash());
                if (separateSalt) pst.setString(idx++, password.getSalt());
                pst.setString(idx++, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not update password for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean updateRealName(String user, String realName) {
        return updateSingleString(user, col.REAL_NAME, realName);
    }

    @Override
    public boolean updateIp(String user, String ip) {
        return updateSingleString(user, col.LAST_IP, ip);
    }

    @Override
    public boolean updateEmail(String user, String email) {
        return updateSingleString(user, col.EMAIL, email);
    }

    @Override
    public boolean updateTotpKey(String user, String totpKey) {
        if (col.TOTP_KEY == null || col.TOTP_KEY.isEmpty()) return false;
        return updateSingleString(user, col.TOTP_KEY, totpKey);
    }

    @Override
    public boolean updatePremiumUuid(String user, UUID premiumUuid) {
        if (!col.hasPremiumUuidColumn()) return false;
        return updateSingleString(user, col.PREMIUM_UUID, premiumUuid == null ? null : premiumUuid.toString());
    }

    private boolean updateSingleString(String user, String column, String value) {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(column) + "=? WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, value);
                pst.setString(2, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not update " + column + " for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean updateLastLogin(String user, long lastLogin) {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.LAST_LOGIN) + "=? WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setLong(1, lastLogin);
                pst.setString(2, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not update lastlogin for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean updateLocation(String user, double x, double y, double z, float yaw, float pitch, String world) {
        String sql = "UPDATE " + quote(settings.table) + " SET "
            + quote(col.LASTLOC_X) + "=?, " + quote(col.LASTLOC_Y) + "=?, " + quote(col.LASTLOC_Z) + "=?, "
            + quote(col.LASTLOC_YAW) + "=?, " + quote(col.LASTLOC_PITCH) + "=?, " + quote(col.LASTLOC_WORLD)
            + "=? WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setDouble(1, x);
                pst.setDouble(2, y);
                pst.setDouble(3, z);
                pst.setFloat(4, yaw);
                pst.setFloat(5, pitch);
                pst.setString(6, world);
                pst.setString(7, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not update location for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }
    public boolean setLogged(String user, boolean logged) {
        return updateSingleInt(user, col.IS_LOGGED, logged ? 1 : 0);
    }

    @Override
    public boolean setSession(String user, boolean hasSession) {
        return updateSingleInt(user, col.HAS_SESSION, hasSession ? 1 : 0);
    }

    @Override
    public boolean isLogged(String user) {
        String sql = "SELECT " + quote(col.IS_LOGGED) + " FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    return rs.next() && rs.getInt(1) == 1;
                }
            }
        } catch (SQLException e) {
            Log.error("Could not check logged status for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    private boolean updateSingleInt(String user, String column, int value) {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(column) + "=? WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setInt(1, value);
                pst.setString(2, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not update " + column + " for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean removeAuth(String user) {
        String sql = "DELETE FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                return pst.executeUpdate() > 0;
            }
        } catch (SQLException e) {
            Log.error("Could not remove auth for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public int countAuths() {
        String sql = "SELECT COUNT(*) FROM " + quote(settings.table) + ";";
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
                return rs.next() ? rs.getInt(1) : 0;
            }
        } catch (SQLException e) {
            Log.error("Could not count auths", e);
            return 0;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public List<String> getRegisteredNames() {
        List<String> names = new ArrayList<>();
        String sql = "SELECT " + quote(col.NAME) + " FROM " + quote(settings.table) + ";";
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
                while (rs.next()) {
                    names.add(rs.getString(1));
                }
            }
        } catch (SQLException e) {
            Log.error("Could not list auths", e);
        } finally {
            releaseConnection(c);
        }
        return names;
    }

    @Override
    public List<String> getLoggedPlayersWithEmptyMail() {
        List<String> players = new ArrayList<>();
        String sql = "SELECT " + quote(col.REAL_NAME) + " FROM " + quote(settings.table)
            + " WHERE " + quote(col.IS_LOGGED) + " = 1 AND ("
            + quote(col.EMAIL) + " = '' OR " + quote(col.EMAIL) + " IS NULL);";
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery(sql)) {
                while (rs.next()) {
                    players.add(rs.getString(1));
                }
            }
        } catch (SQLException e) {
            Log.error("Could not query logged players with empty mail", e);
        } finally {
            releaseConnection(c);
        }
        return players;
    }

    @Override
    public void reload() {
        pool.close();
        try {
            initDriver();
        } catch (SQLException e) {
            Log.error("Could not reload database driver", e);
            return;
        }
        initPool();
        try {
            createSchemaAndColumns();
        } catch (SQLException e) {
            Log.error("Could not recreate schema after reload", e);
        }
    }

    @Override
    public void close() {
        pool.close();
    }

    // ---------------------------------------------------------------- helpers

    protected PlayerAuth buildAuthFromResultSet(ResultSet rs) throws SQLException {
        String salt = col.hasSaltColumn() ? rs.getString(col.SALT) : null;
        UUID uuid = col.hasPlayerUuidColumn() ? parseUuidSafely(rs.getString(col.PLAYER_UUID)) : null;
        UUID premiumUuid = col.hasPremiumUuidColumn() ? parseUuidSafely(rs.getString(col.PREMIUM_UUID)) : null;
        Long lastLogin = getNullableLong(rs, col.LAST_LOGIN);
        String totp = (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) ? rs.getString(col.TOTP_KEY) : null;
        return PlayerAuth.builder()
            .name(rs.getString(col.NAME))
            .realName(rs.getString(col.REAL_NAME))
            .password(rs.getString(col.PASSWORD), salt)
            .lastIp(rs.getString(col.LAST_IP))
            .email(rs.getString(col.EMAIL))
            .lastLogin(lastLogin)
            .registrationDate(rs.getLong(col.REGISTRATION_DATE))
            .registrationIp(rs.getString(col.REGISTRATION_IP))
            .locX(rs.getDouble(col.LASTLOC_X))
            .locY(rs.getDouble(col.LASTLOC_Y))
            .locZ(rs.getDouble(col.LASTLOC_Z))
            .locWorld(rs.getString(col.LASTLOC_WORLD))
            .locYaw(rs.getFloat(col.LASTLOC_YAW))
            .locPitch(rs.getFloat(col.LASTLOC_PITCH))
            .totpKey(totp)
            .uuid(uuid)
            .premiumUuid(premiumUuid)
            .build();
    }

    protected static Long getNullableLong(ResultSet rs, String columnLabel) throws SQLException {
        long v = rs.getLong(columnLabel);
        return rs.wasNull() ? null : v;
    }

    protected static void setNullableLong(PreparedStatement pst, int idx, Long value) throws SQLException {
        if (value == null) {
            pst.setNull(idx, java.sql.Types.BIGINT);
        } else {
            pst.setLong(idx, value);
        }
    }

    protected static UUID parseUuidSafely(String value) {
        if (value == null || value.isEmpty()) return null;
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    protected boolean isColumnMissing(DatabaseMetaData md, String columnName) throws SQLException {
        String catalog = (settings.database == null || settings.database.isEmpty()) ? null : settings.database;
        try (ResultSet rs = md.getColumns(catalog, null, settings.table, columnName)) {
            return !rs.next();
        }
    }

    protected void exec(Statement st, String sql) throws SQLException {
        st.executeUpdate(sql);
    }

    /**
     * Identifier quoting; overridden by backends that require it (e.g. SQLite reserves some names).
     *
     * @return the identifier, optionally quoted
     */
    protected String quote(String identifier) {
        return identifier;
    }
}