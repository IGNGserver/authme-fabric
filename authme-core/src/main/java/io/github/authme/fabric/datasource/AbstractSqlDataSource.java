package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.SecureFileAccess;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
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

    private static final int MAX_PREMIUM_NAMES = 16_384;
    private static final int CURRENT_SCHEMA_VERSION = 3;
    private static final long LOGIN_LEASE_MILLIS = 30_000L;

    protected final DbSettings settings;
    protected final Columns col;
    protected SimpleConnectionPool pool;

    protected AbstractSqlDataSource(DbSettings settings) throws SQLException {
        this(settings, settings.schemaMode == DbSettings.SchemaMode.MIGRATE, null, true);
    }

    /**
     * Constructor used by schema-unmanaged and read-only consumers. The JDBC URL override is
     * resolved before the pool is created and {@code createSchema=false} guarantees that this
     * process never issues schema DDL. Remote databases must additionally use a SELECT-only
     * principal because JDBC cannot enforce server-side privileges.
     */
    protected AbstractSqlDataSource(DbSettings settings, boolean createSchema,
                                    String jdbcUrlOverride) throws SQLException {
        this(settings, createSchema, jdbcUrlOverride, true);
    }

    protected AbstractSqlDataSource(DbSettings settings, boolean createSchema,
                                    String jdbcUrlOverride, boolean validateRuntimeState)
        throws SQLException {
        this.settings = settings;
        this.col = settings.columns;
        validateIdentifiers();
        initDriver();
        initPool(jdbcUrlOverride == null ? buildJdbcUrl() : jdbcUrlOverride);
        try {
            if (createSchema) runVersionedMigrations();
            else {
                validateSchemaAndColumns();
                if (validateRuntimeState) {
                    validateSecurityStateSchema();
                    validateLoginLeaseSchema();
                }
            }
        } catch (SQLException e) {
            pool.close();
            throw e;
        }
        if (!createSchema) {
            Log.info(getType() + " schema-unmanaged data source initialised (table=" + settings.table + ")");
            return;
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
        initPool(buildJdbcUrl());
    }

    private void initPool(String jdbcUrl) {
        this.pool = new SimpleConnectionPool(jdbcUrl, jdbcProps(), Math.max(2, settings.poolSize),
            Math.max(0, settings.maxLifetimeSeconds));
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

    /**
     * Versioned, restart-safe schema entrypoint. The history row is marked unsuccessful before
     * DDL begins, so a partial backend DDL commit is detected and the idempotent migration is
     * resumed instead of being mistaken for a complete upgrade.
     */
    private void runVersionedMigrations() throws SQLException {
        Connection lockConnection = null;
        boolean locked = false;
        try {
            if (getType() != DataSourceType.SQLITE) {
                lockConnection = borrowConnection();
                locked = acquireAdvisoryLock(lockConnection, "migration");
                if (!locked) {
                    throw new SQLException("Could not acquire AuthMe schema migration lock");
                }
            }
            runVersionedMigrationsUnlocked();
        } finally {
            if (lockConnection != null && locked) {
                releaseAdvisoryLock(lockConnection, "migration");
            }
            releaseConnection(lockConnection);
        }
    }

    private void runVersionedMigrationsUnlocked() throws SQLException {
        String history = quote(settings.table + "_schema_history");
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement()) {
                st.executeUpdate("CREATE TABLE IF NOT EXISTS " + history
                    + " (version INTEGER PRIMARY KEY, success SMALLINT NOT NULL, installed_at BIGINT NOT NULL);");
            }
            boolean complete = false;
            try (PreparedStatement select = c.prepareStatement(
                "SELECT success FROM " + history + " WHERE version=?;")) {
                select.setInt(1, CURRENT_SCHEMA_VERSION);
                try (ResultSet rs = select.executeQuery()) {
                    complete = rs.next() && rs.getInt(1) != 0;
                }
            }
            if (complete) {
                try {
                    validateSchemaAndColumns();
                    validateSecurityStateSchema();
                    validateLoginLeaseSchema();
                    return;
                } catch (SQLException changedConfiguration) {
                    // Configurable column names can require the same idempotent migration step to
                    // run again. The dirty marker below keeps that recovery explicit and visible.
                }
            }
            int updated;
            try (PreparedStatement mark = c.prepareStatement(
                "UPDATE " + history + " SET success=0, installed_at=? WHERE version=?;")) {
                mark.setLong(1, System.currentTimeMillis());
                mark.setInt(2, CURRENT_SCHEMA_VERSION);
                updated = mark.executeUpdate();
            }
            if (updated == 0) {
                try (PreparedStatement insert = c.prepareStatement(
                    "INSERT INTO " + history + " (version, success, installed_at) VALUES (?, 0, ?);")) {
                    insert.setInt(1, CURRENT_SCHEMA_VERSION);
                    insert.setLong(2, System.currentTimeMillis());
                    insert.executeUpdate();
                }
            }
        } finally {
            releaseConnection(c);
        }

        createSchemaAndColumns();
        createSecurityStateSchema();
        createLoginLeaseSchema();
        validateSchemaAndColumns();
        validateSecurityStateSchema();
        validateLoginLeaseSchema();

        try {
            c = borrowConnection();
            try (PreparedStatement done = c.prepareStatement(
                "UPDATE " + history + " SET success=1, installed_at=? WHERE version=?;")) {
                done.setLong(1, System.currentTimeMillis());
                done.setInt(2, CURRENT_SCHEMA_VERSION);
                if (done.executeUpdate() != 1) {
                    throw new SQLException("Could not commit AuthMe schema history version "
                        + CURRENT_SCHEMA_VERSION);
                }
            }
        } finally {
            releaseConnection(c);
        }
    }

    private String securityStateTable() {
        return settings.table + "_security_state";
    }

    private String loginLeaseTable() {
        return settings.table + "_login_leases";
    }

    private void createSecurityStateSchema() throws SQLException {
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement()) {
                st.executeUpdate("CREATE TABLE IF NOT EXISTS " + quote(securityStateTable()) + " ("
                    + quote("state_key") + " VARCHAR(191) PRIMARY KEY, "
                    + quote("attempts") + " INTEGER NOT NULL, "
                    + quote("window_started") + " BIGINT NOT NULL, "
                    + quote("last_failure") + " BIGINT NOT NULL, "
                    + quote("banned_until") + " BIGINT NOT NULL);");
            }
        } finally {
            releaseConnection(c);
        }
    }

    private void validateSecurityStateSchema() throws SQLException {
        Connection c = null;
        String sql = "SELECT " + quote("state_key") + "," + quote("attempts") + ','
            + quote("window_started") + ',' + quote("last_failure") + ',' + quote("banned_until")
            + " FROM " + quote(securityStateTable()) + " WHERE 1=0;";
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet ignored = st.executeQuery(sql)) {
                // Preparing/executing this empty projection validates the auxiliary runtime schema.
            }
        } catch (SQLException exception) {
            throw new SQLException("AuthMe shared security-state schema is missing or invalid. Run "
                + "once with schemaManagement=MIGRATE using a migration principal.", exception);
        } finally {
            releaseConnection(c);
        }
    }

    private void createLoginLeaseSchema() throws SQLException {
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement()) {
                st.executeUpdate("CREATE TABLE IF NOT EXISTS " + quote(loginLeaseTable()) + " ("
                    + quote("username") + " VARCHAR(191) PRIMARY KEY, "
                    + quote("ip") + " VARCHAR(64) NOT NULL, "
                    + quote("lease_version") + " BIGINT NOT NULL, "
                    + quote("expires_at") + " BIGINT NOT NULL);");
            }
        } finally {
            releaseConnection(c);
        }
    }

    private void validateLoginLeaseSchema() throws SQLException {
        Connection c = null;
        String sql = "SELECT " + quote("username") + ',' + quote("ip") + ','
            + quote("lease_version") + ',' + quote("expires_at") + " FROM "
            + quote(loginLeaseTable()) + " WHERE 1=0;";
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet ignored = st.executeQuery(sql)) {
                // Empty projection validates the lease table without mutating it.
            }
        } catch (SQLException exception) {
            throw new SQLException("AuthMe login-lease schema is missing or invalid. Run once with "
                + "schemaManagement=MIGRATE using a migration principal.", exception);
        } finally {
            releaseConnection(c);
        }
    }

    /** Validates every column consumed by the runtime without changing the database. */
    protected void validateSchemaAndColumns() throws SQLException {
        List<String> required = new ArrayList<>(List.of(
            col.ID, col.NAME, col.REAL_NAME, col.PASSWORD, col.LAST_IP, col.LAST_LOGIN,
            col.REGISTRATION_DATE, col.REGISTRATION_IP, col.LASTLOC_X, col.LASTLOC_Y,
            col.LASTLOC_Z, col.LASTLOC_WORLD, col.LASTLOC_YAW, col.LASTLOC_PITCH,
            col.EMAIL, col.IS_LOGGED, col.HAS_SESSION));
        if (col.hasSaltColumn()) required.add(col.SALT);
        if (col.TOTP_KEY != null && !col.TOTP_KEY.isBlank()) required.add(col.TOTP_KEY);
        if (col.hasPlayerUuidColumn()) required.add(col.PLAYER_UUID);
        if (col.hasPremiumUuidColumn()) required.add(col.PREMIUM_UUID);
        Connection con = null;
        try {
            con = borrowConnection();
            DatabaseMetaData metadata = con.getMetaData();
            for (String column : required) {
                if (column == null || column.isBlank() || isColumnMissing(metadata, column)) {
                    throw new SQLException("AuthMe schema validation failed: missing column " + column
                        + " in table " + settings.table + ". Run once with schemaManagement=MIGRATE "
                        + "using a migration principal, then restore VALIDATE mode.");
                }
            }
        } finally {
            releaseConnection(con);
        }
    }

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
        return lookupAuth(user).auth();
    }

    @Override
    public DataSource.LookupResult lookupAuth(String user) {
        String sql = "SELECT * FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    if (rs.next()) {
                        return new DataSource.LookupResult(buildAuthFromResultSet(rs), true);
                    }
                }
            }
        } catch (SQLException e) {
            Log.error("Could not fetch auth for " + user, e);
            return new DataSource.LookupResult(null, false);
        } finally {
            releaseConnection(c);
        }
        return new DataSource.LookupResult(null, true);
    }

    @Override
    public boolean isAuthAvailable(String user) {
        return checkAuthAvailable(user).available();
    }

    @Override
    public DataSource.CheckResult checkAuthAvailable(String user) {
        String sql = "SELECT 1 FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    return new DataSource.CheckResult(rs.next(), true);
                }
            }
        } catch (SQLException e) {
            Log.error("Could not check auth availability for " + user, e);
            return new DataSource.CheckResult(false, false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean setLoginState(String user, String ip, long lastLogin, boolean hasSession) {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.IS_LOGGED) + "=?, "
            + quote(col.LAST_IP) + "=?, " + quote(col.LAST_LOGIN) + "=?, "
            + quote(col.HAS_SESSION) + "=? WHERE " + quote(col.NAME) + "=?;";
        return inTransaction(sql, pst -> {
            pst.setBoolean(1, true);
            pst.setString(2, ip == null ? "" : ip);
            pst.setLong(3, lastLogin);
            pst.setBoolean(4, hasSession);
            pst.setString(5, user.toLowerCase(Locale.ROOT));
        }, user);
    }

    @Override
    public DataSource.LoginStateResult acquireLoginState(String user, String ip, long requestedVersion,
                                                         boolean hasSession, int maxLoggedPerIp) {
        Connection c = null;
        boolean locked = false;
        boolean sqliteTransaction = false;
        boolean transaction = false;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            transaction = true;
            if (getType() == DataSourceType.SQLITE) {
                sqliteTransaction = true;
                // A harmless write takes SQLite's cross-process write lock before count/update.
                try (PreparedStatement lock = c.prepareStatement("UPDATE "
                    + quote(settings.table + "_schema_history")
                    + " SET installed_at=installed_at WHERE version=?;")) {
                    lock.setInt(1, CURRENT_SCHEMA_VERSION);
                    lock.executeUpdate();
                }
                locked = true;
            } else {
                locked = acquireAdvisoryLock(c, "login");
            }
            if (!locked) return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ERROR, 0L);

            long now = System.currentTimeMillis();
            long currentVersion = 0L;
            String normalizedUser = user == null ? "" : user.toLowerCase(Locale.ROOT);
            try (PreparedStatement current = c.prepareStatement("SELECT " + quote(col.LAST_LOGIN)
                + " FROM " + quote(settings.table) + " WHERE " + quote(col.NAME) + "=?;")) {
                current.setString(1, normalizedUser);
                try (ResultSet rs = current.executeQuery()) {
                    if (!rs.next()) {
                        rollbackSqlite(c, transaction);
                        return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ERROR, 0L);
                    }
                    currentVersion = Math.max(0L, rs.getLong(1));
                }
            }

            String leaseTable = quote(loginLeaseTable());
            try (PreparedStatement expired = c.prepareStatement("DELETE FROM " + leaseTable
                + " WHERE " + quote("expires_at") + "<?;")) {
                expired.setLong(1, now);
                expired.executeUpdate();
            }
            try (PreparedStatement currentLease = c.prepareStatement("SELECT "
                + quote("lease_version") + " FROM " + leaseTable + " WHERE "
                + quote("username") + "=?;")) {
                currentLease.setString(1, normalizedUser);
                try (ResultSet rs = currentLease.executeQuery()) {
                    if (rs.next()) currentVersion = Math.max(currentVersion, rs.getLong(1));
                }
            }

            if (maxLoggedPerIp > 0 && ip != null && !ip.isBlank() && !"unknown".equals(ip)) {
                String countSql = "SELECT COUNT(*) FROM " + leaseTable + " WHERE "
                    + quote("ip") + "=? AND " + quote("username") + "<>? AND "
                    + quote("expires_at") + ">=?;";
                try (PreparedStatement count = c.prepareStatement(countSql)) {
                    count.setString(1, ip);
                    count.setString(2, normalizedUser);
                    count.setLong(3, now);
                    try (ResultSet rs = count.executeQuery()) {
                        if (rs.next() && rs.getInt(1) >= maxLoggedPerIp) {
                            commitSqlite(c, transaction);
                            return new DataSource.LoginStateResult(
                                DataSource.LoginStateStatus.LIMIT_REACHED, 0L);
                        }
                    }
                }
            }

            if (currentVersion == Long.MAX_VALUE) {
                rollbackSqlite(c, transaction);
                Log.error("Could not acquire coordinated login state: stored fence is exhausted");
                return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ERROR, 0L);
            }
            long version = Math.max(Math.max(1L, requestedVersion), currentVersion + 1L);
            String updateSql = "UPDATE " + quote(settings.table) + " SET "
                + quote(col.IS_LOGGED) + "=?, " + quote(col.LAST_IP) + "=?, "
                + quote(col.LAST_LOGIN) + "=?, " + quote(col.HAS_SESSION) + "=? WHERE "
                + quote(col.NAME) + "=?;";
            try (PreparedStatement update = c.prepareStatement(updateSql)) {
                update.setBoolean(1, true);
                update.setString(2, ip);
                update.setLong(3, version);
                update.setBoolean(4, hasSession);
                update.setString(5, normalizedUser);
                if (update.executeUpdate() != 1) {
                    rollbackSqlite(c, transaction);
                    return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ERROR, 0L);
                }
            }

            int leaseUpdated;
            try (PreparedStatement updateLease = c.prepareStatement("UPDATE " + leaseTable + " SET "
                + quote("ip") + "=?," + quote("lease_version") + "=?,"
                + quote("expires_at") + "=? WHERE " + quote("username") + "=?;")) {
                updateLease.setString(1, ip == null ? "" : ip);
                updateLease.setLong(2, version);
                updateLease.setLong(3, safeAdd(now, LOGIN_LEASE_MILLIS));
                updateLease.setString(4, normalizedUser);
                leaseUpdated = updateLease.executeUpdate();
            }
            if (leaseUpdated == 0) {
                try (PreparedStatement insertLease = c.prepareStatement("INSERT INTO " + leaseTable
                    + " (" + quote("username") + ',' + quote("ip") + ','
                    + quote("lease_version") + ',' + quote("expires_at") + ") VALUES (?,?,?,?);")) {
                    insertLease.setString(1, normalizedUser);
                    insertLease.setString(2, ip == null ? "" : ip);
                    insertLease.setLong(3, version);
                    insertLease.setLong(4, safeAdd(now, LOGIN_LEASE_MILLIS));
                    insertLease.executeUpdate();
                }
            }
            commitSqlite(c, transaction);
            return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ACQUIRED, version);
        } catch (SQLException e) {
            rollbackSqlite(c, transaction);
            Log.error("Could not acquire coordinated login state", e);
            return new DataSource.LoginStateResult(DataSource.LoginStateStatus.ERROR, 0L);
        } finally {
            if (c != null && locked && !sqliteTransaction) releaseAdvisoryLock(c, "login");
            if (c != null && transaction) {
                try { c.setAutoCommit(true); } catch (SQLException ignored) { }
            }
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.LoginLeaseResult renewLoginLease(String user, long version, long now) {
        if (user == null || user.isBlank() || version <= 0L || now <= 0L) {
            return new DataSource.LoginLeaseResult(false, false);
        }
        String sql = "UPDATE " + quote(loginLeaseTable()) + " SET " + quote("expires_at")
            + "=? WHERE " + quote("username") + "=? AND " + quote("lease_version")
            + "=? AND " + quote("expires_at") + ">=? AND EXISTS (SELECT 1 FROM "
            + quote(settings.table) + " WHERE "
            + quote(col.NAME) + "=? AND " + quote(col.LAST_LOGIN) + "=? AND "
            + quote(col.IS_LOGGED) + "<>0);";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement renew = c.prepareStatement(sql)) {
                renew.setLong(1, safeAdd(now, LOGIN_LEASE_MILLIS));
                renew.setString(2, user.toLowerCase(Locale.ROOT));
                renew.setLong(3, version);
                renew.setLong(4, now);
                renew.setString(5, user.toLowerCase(Locale.ROOT));
                renew.setLong(6, version);
                return new DataSource.LoginLeaseResult(renew.executeUpdate() == 1, true);
            }
        } catch (SQLException exception) {
            Log.error("Could not renew coordinated login lease", exception);
            return new DataSource.LoginLeaseResult(false, false);
        } finally {
            releaseConnection(c);
        }
    }

    private boolean acquireAdvisoryLock(Connection c, String scope) throws SQLException {
        if (getType() == DataSourceType.MYSQL || getType() == DataSourceType.MARIADB) {
            try (PreparedStatement statement = c.prepareStatement("SELECT GET_LOCK(?, 10);")) {
                statement.setString(1, coordinationLockName(scope));
                try (ResultSet rs = statement.executeQuery()) {
                    return rs.next() && rs.getInt(1) == 1;
                }
            }
        }
        if (getType() == DataSourceType.POSTGRESQL) {
            try (PreparedStatement statement = c.prepareStatement("SELECT pg_advisory_lock(?);")) {
                statement.setLong(1, coordinationLockId(scope));
                try (ResultSet rs = statement.executeQuery()) { return rs.next(); }
            }
        }
        return false;
    }

    private void releaseAdvisoryLock(Connection c, String scope) {
        try {
            boolean released = true;
            if (getType() == DataSourceType.MYSQL || getType() == DataSourceType.MARIADB) {
                try (PreparedStatement statement = c.prepareStatement("SELECT RELEASE_LOCK(?);")) {
                    statement.setString(1, coordinationLockName(scope));
                    try (ResultSet rs = statement.executeQuery()) {
                        released = rs.next() && rs.getInt(1) == 1;
                    }
                }
            } else if (getType() == DataSourceType.POSTGRESQL) {
                try (PreparedStatement statement = c.prepareStatement("SELECT pg_advisory_unlock(?);")) {
                    statement.setLong(1, coordinationLockId(scope));
                    try (ResultSet rs = statement.executeQuery()) {
                        released = rs.next() && rs.getBoolean(1);
                    }
                }
            }
            if (!released) throw new SQLException("Database coordination lock was not owned");
        } catch (SQLException e) {
            Log.error("Could not release database coordination lock", e);
            // Advisory locks are connection-scoped. Never return a connection with an uncertain
            // lock state to the pool, or a later borrower could retain the lock indefinitely.
            try { c.close(); } catch (SQLException ignored) { }
        }
    }

    private String coordinationLockName(String scope) {
        String value = "authme:" + settings.database + ':' + settings.table + ':' + scope;
        return value.length() <= 64 ? value : value.substring(0, 64);
    }

    private long coordinationLockId(String scope) {
        String value = coordinationLockName(scope);
        long hash = 0xcbf29ce484222325L;
        for (int i = 0; i < value.length(); i++) {
            hash ^= value.charAt(i);
            hash *= 0x100000001b3L;
        }
        return hash;
    }

    private static void commitSqlite(Connection c, boolean transaction) throws SQLException {
        if (transaction) c.commit();
    }

    private static void rollbackSqlite(Connection c, boolean transaction) {
        if (!transaction || c == null) return;
        try { c.rollback(); } catch (SQLException ignored) { }
    }

    private static long safeAdd(long value, long delta) {
        return value > Long.MAX_VALUE - delta ? Long.MAX_VALUE : value + delta;
    }

    @Override
    public boolean setLoginFlags(String user, boolean logged, boolean hasSession) {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.IS_LOGGED) + "=?, "
            + quote(col.HAS_SESSION) + "=? WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setBoolean(1, logged);
                pst.setBoolean(2, hasSession);
                pst.setString(3, user.toLowerCase(Locale.ROOT));
                pst.executeUpdate();
            }
            if (!logged) deleteAllLoginLeases(c, user);
            c.commit();
            return true;
        } catch (SQLException exception) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not update login flags for " + user, exception);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean persistDisconnect(String user, long lastLogin, double x, double y, double z,
                                     float yaw, float pitch, String world, boolean saveLocation,
                                     boolean keepSession) {
        StringBuilder sql = new StringBuilder("UPDATE ").append(quote(settings.table)).append(" SET ")
            .append(quote(col.LAST_LOGIN)).append("=?");
        if (saveLocation) {
            sql.append(", ").append(quote(col.LASTLOC_X)).append("=?")
                .append(", ").append(quote(col.LASTLOC_Y)).append("=?")
                .append(", ").append(quote(col.LASTLOC_Z)).append("=?")
                .append(", ").append(quote(col.LASTLOC_YAW)).append("=?")
                .append(", ").append(quote(col.LASTLOC_PITCH)).append("=?")
                .append(", ").append(quote(col.LASTLOC_WORLD)).append("=?");
        }
        sql.append(", ").append(quote(col.IS_LOGGED)).append("=?")
            .append(", ").append(quote(col.HAS_SESSION)).append("=? WHERE ")
            .append(quote(col.NAME)).append("=?;");
        return inTransaction(sql.toString(), pst -> {
            int i = 1;
            pst.setLong(i++, lastLogin);
            if (saveLocation) {
                pst.setDouble(i++, x);
                pst.setDouble(i++, y);
                pst.setDouble(i++, z);
                pst.setFloat(i++, yaw);
                pst.setFloat(i++, pitch);
                pst.setString(i++, world == null ? "world" : world);
            }
            pst.setBoolean(i++, false);
            pst.setBoolean(i++, keepSession);
            pst.setString(i, user.toLowerCase(Locale.ROOT));
        }, user);
    }

    @Override
    public boolean persistDisconnectIfLastLogin(String user, long expectedLastLogin, long lastLogin,
                                                 double x, double y, double z, float yaw, float pitch,
                                                 String world, boolean saveLocation, boolean keepSession) {
        if (expectedLastLogin <= 0L) return false;
        StringBuilder sql = new StringBuilder("UPDATE ").append(quote(settings.table)).append(" SET ")
            .append(quote(col.LAST_LOGIN)).append("=?");
        if (saveLocation) {
            sql.append(", ").append(quote(col.LASTLOC_X)).append("=?")
                .append(", ").append(quote(col.LASTLOC_Y)).append("=?")
                .append(", ").append(quote(col.LASTLOC_Z)).append("=?")
                .append(", ").append(quote(col.LASTLOC_YAW)).append("=?")
                .append(", ").append(quote(col.LASTLOC_PITCH)).append("=?")
                .append(", ").append(quote(col.LASTLOC_WORLD)).append("=?");
        }
        sql.append(", ").append(quote(col.IS_LOGGED)).append("=?")
            .append(", ").append(quote(col.HAS_SESSION)).append("=? WHERE ")
            .append(quote(col.NAME)).append("=? AND ").append(quote(col.LAST_LOGIN)).append("=?;");
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            try (PreparedStatement pst = c.prepareStatement(sql.toString())) {
                int i = 1;
                pst.setLong(i++, lastLogin);
                if (saveLocation) {
                    pst.setDouble(i++, x);
                    pst.setDouble(i++, y);
                    pst.setDouble(i++, z);
                    pst.setFloat(i++, yaw);
                    pst.setFloat(i++, pitch);
                    pst.setString(i++, world == null ? "world" : world);
                }
                pst.setBoolean(i++, false);
                pst.setBoolean(i++, keepSession);
                pst.setString(i++, user.toLowerCase(Locale.ROOT));
                pst.setLong(i, expectedLastLogin);
                pst.executeUpdate();
            }
            deleteLoginLease(c, user, expectedLastLogin);
            c.commit();
            return true;
        } catch (SQLException e) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not conditionally persist disconnect for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean clearLoginIfLastLogin(String user, long expectedLastLogin) {
        if (expectedLastLogin <= 0L) return false;
        String sql = "UPDATE " + quote(settings.table) + " SET "
            + quote(col.IS_LOGGED) + "=?, " + quote(col.HAS_SESSION) + "=? WHERE "
            + quote(col.NAME) + "=? AND " + quote(col.LAST_LOGIN) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setBoolean(1, false);
                pst.setBoolean(2, false);
                pst.setString(3, user.toLowerCase(Locale.ROOT));
                pst.setLong(4, expectedLastLogin);
                pst.executeUpdate();
            }
            deleteLoginLease(c, user, expectedLastLogin);
            c.commit();
            return true;
        } catch (SQLException e) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not conditionally clear login state for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    private void deleteLoginLease(Connection c, String user, long version) throws SQLException {
        try (PreparedStatement delete = c.prepareStatement("DELETE FROM " + quote(loginLeaseTable())
            + " WHERE " + quote("username") + "=? AND " + quote("lease_version") + "=?;")) {
            delete.setString(1, user.toLowerCase(Locale.ROOT));
            delete.setLong(2, version);
            delete.executeUpdate();
        }
    }

    private void deleteAllLoginLeases(Connection c, String user) throws SQLException {
        try (PreparedStatement delete = c.prepareStatement("DELETE FROM " + quote(loginLeaseTable())
            + " WHERE " + quote("username") + "=?;")) {
            delete.setString(1, user.toLowerCase(Locale.ROOT));
            delete.executeUpdate();
        }
    }

    @Override
    public PlayerAuth getAuthByEmail(String email) {
        if (email == null || email.isBlank()) return null;
        String sql = "SELECT * FROM " + quote(settings.table) + " WHERE LOWER(" + quote(col.EMAIL) + ")=LOWER(?);";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, email.trim());
                try (ResultSet rs = pst.executeQuery()) {
                    return rs.next() ? buildAuthFromResultSet(rs) : null;
                }
            }
        } catch (SQLException e) {
            Log.error("Could not fetch account by e-mail", e);
            return null;
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
    public boolean updatePasswordIfMatches(String user, HashedPassword expected,
                                           HashedPassword replacement) {
        if (expected == null || replacement == null || expected.getHash() == null
            || replacement.getHash() == null) return false;
        boolean replacementSalt = col.hasSaltColumn() && replacement.getSalt() != null;
        StringBuilder sql = new StringBuilder("UPDATE ").append(quote(settings.table))
            .append(" SET ").append(quote(col.PASSWORD)).append("=?");
        if (replacementSalt) sql.append(", ").append(quote(col.SALT)).append("=?");
        sql.append(" WHERE ").append(quote(col.NAME)).append("=? AND ")
            .append(quote(col.PASSWORD)).append("=?");
        if (col.hasSaltColumn()) {
            if (expected.getSalt() == null) {
                // AuthMe treats NULL and an empty legacy salt as the same no-salt value.
                sql.append(" AND (").append(quote(col.SALT)).append(" IS NULL OR ")
                    .append(quote(col.SALT)).append("='')");
            } else {
                sql.append(" AND ").append(quote(col.SALT)).append("=?");
            }
        }
        sql.append(';');
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql.toString())) {
                int index = 1;
                pst.setString(index++, replacement.getHash());
                if (replacementSalt) pst.setString(index++, replacement.getSalt());
                pst.setString(index++, user.toLowerCase(Locale.ROOT));
                pst.setString(index++, expected.getHash());
                if (col.hasSaltColumn() && expected.getSalt() != null) {
                    pst.setString(index, expected.getSalt());
                }
                return pst.executeUpdate() == 1;
            }
        } catch (SQLException e) {
            Log.error("Could not conditionally update password for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public boolean updatePasswordAndClearLogin(String user, HashedPassword password) {
        boolean separateSalt = col.hasSaltColumn() && password.getSalt() != null;
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.PASSWORD) + "=?"
            + (separateSalt ? ", " + quote(col.SALT) + "=?" : "")
            + ", " + quote(col.IS_LOGGED) + "=?, " + quote(col.HAS_SESSION) + "=?"
            + " WHERE " + quote(col.NAME) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            try (PreparedStatement statement = c.prepareStatement(sql)) {
                int index = 1;
                statement.setString(index++, password.getHash());
                if (separateSalt) statement.setString(index++, password.getSalt());
                statement.setBoolean(index++, false);
                statement.setBoolean(index++, false);
                statement.setString(index, user.toLowerCase(Locale.ROOT));
                if (statement.executeUpdate() != 1) {
                    c.rollback();
                    return false;
                }
            }
            deleteAllLoginLeases(c, user);
            c.commit();
            return true;
        } catch (SQLException exception) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not update password and revoke sessions for " + user, exception);
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

    @Override
    public boolean resetAllLocations() {
        String sql = "UPDATE " + quote(settings.table) + " SET "
            + quote(col.LASTLOC_X) + "=0, " + quote(col.LASTLOC_Y) + "=64, "
            + quote(col.LASTLOC_Z) + "=0, " + quote(col.LASTLOC_YAW) + "=0, "
            + quote(col.LASTLOC_PITCH) + "=0, " + quote(col.LASTLOC_WORLD) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, "minecraft:overworld");
                pst.executeUpdate();
                return true;
            }
        } catch (SQLException e) {
            Log.error("Could not reset all stored locations", e);
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
            c.setAutoCommit(false);
            int affected;
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user.toLowerCase(Locale.ROOT));
                affected = pst.executeUpdate();
            }
            deleteAllLoginLeases(c, user);
            c.commit();
            return affected > 0;
        } catch (SQLException e) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
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
    public boolean ping() {
        Connection c = null;
        try {
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT 1;")) {
                return rs.next();
            }
        } catch (SQLException e) {
            Log.error("Database health check failed", e);
            return false;
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
    public DataSource.QueryResult<List<String>> queryRegisteredNamesByIp(String ip) {
        List<String> names = new ArrayList<>();
        String sql = "SELECT " + quote(col.NAME) + " FROM " + quote(settings.table)
            + " WHERE " + quote(col.LAST_IP) + "=? ORDER BY " + quote(col.REGISTRATION_DATE)
            + " ASC LIMIT 10000;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, ip == null ? "" : ip);
                try (ResultSet rs = pst.executeQuery()) {
                    while (rs.next() && names.size() < 10_000) names.add(rs.getString(1));
                }
            }
            return new DataSource.QueryResult<>(names, true);
        } catch (SQLException e) {
            Log.error("Could not list accounts by last IP", e);
            return new DataSource.QueryResult<>(List.of(), false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.CountResult countRegisteredByIp(String ip) {
        return countWhere(col.REGISTRATION_IP, ip, "registration IP");
    }

    @Override
    public DataSource.CountResult countLoggedByIp(String ip) {
        String sql = "SELECT COUNT(*) FROM " + quote(settings.table) + " WHERE "
            + quote(col.IS_LOGGED) + "=? AND " + quote(col.LAST_IP) + "=?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setBoolean(1, true);
                pst.setString(2, ip == null ? "" : ip);
                try (ResultSet rs = pst.executeQuery()) {
                    return new DataSource.CountResult(rs.next() ? rs.getInt(1) : 0, true);
                }
            }
        } catch (SQLException e) {
            Log.error("Could not count logged accounts by IP", e);
            return new DataSource.CountResult(0, false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.CountResult countRegisteredByEmail(String email) {
        String sql = "SELECT COUNT(*) FROM " + quote(settings.table) + " WHERE LOWER(" + quote(col.EMAIL)
            + ")=LOWER(?) AND " + quote(col.EMAIL) + " IS NOT NULL AND " + quote(col.EMAIL) + "<>'';";
        return count(sql, email == null ? "" : email.trim(), "e-mail");
    }

    @Override
    public DataSource.QueryResult<List<String>> queryPremiumUsernames() {
        List<String> names = new ArrayList<>();
        if (!col.hasPremiumUuidColumn()) return new DataSource.QueryResult<>(names, true);
        String sql = "SELECT " + quote(col.NAME) + " FROM " + quote(settings.table)
            + " WHERE " + quote(col.PREMIUM_UUID) + " IS NOT NULL AND " + quote(col.PREMIUM_UUID)
            + "<>'' LIMIT ?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setInt(1, MAX_PREMIUM_NAMES);
                try (ResultSet rs = pst.executeQuery()) {
                    while (rs.next() && names.size() < MAX_PREMIUM_NAMES) names.add(rs.getString(1));
                }
            }
            return new DataSource.QueryResult<>(names, true);
        } catch (SQLException e) {
            Log.error("Could not query premium usernames", e);
            return new DataSource.QueryResult<>(List.of(), false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.CheckResult checkPremiumUsername(String user) {
        if (!col.hasPremiumUuidColumn()) return new DataSource.CheckResult(false, true);
        String sql = "SELECT 1 FROM " + quote(settings.table) + " WHERE " + quote(col.NAME)
            + "=? AND " + quote(col.PREMIUM_UUID) + " IS NOT NULL AND "
            + quote(col.PREMIUM_UUID) + "<>'';";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, user == null ? "" : user.toLowerCase(Locale.ROOT));
                try (ResultSet rs = pst.executeQuery()) {
                    return new DataSource.CheckResult(rs.next(), true);
                }
            }
        } catch (SQLException e) {
            Log.error("Could not check Premium status", e);
            return new DataSource.CheckResult(false, false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.FailureStateResult readFailureState(String key, long now, long windowMillis) {
        if (key == null || key.isBlank() || key.length() > 191) {
            return failedFailureState();
        }
        Connection c = null;
        try {
            c = borrowConnection();
            DataSource.FailureStateResult state = selectFailureState(c, key);
            if (!state.successful()) return state;
            if (state.windowStarted() > 0L && now - state.windowStarted() > Math.max(1L, windowMillis)
                && state.bannedUntil() <= now) {
                return emptyFailureState();
            }
            return state;
        } catch (SQLException exception) {
            Log.error("Could not read shared authentication failure state", exception);
            return failedFailureState();
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.FailureStateResult recordFailureState(String key, long now, long windowMillis,
                                                            int banThreshold, long banMillis) {
        if (key == null || key.isBlank() || key.length() > 191) return failedFailureState();
        Connection c = null;
        boolean locked = false;
        boolean sqliteTransaction = false;
        try {
            c = borrowConnection();
            if (getType() == DataSourceType.SQLITE) {
                c.setAutoCommit(false);
                sqliteTransaction = true;
                try (PreparedStatement lock = c.prepareStatement("UPDATE "
                    + quote(settings.table + "_schema_history")
                    + " SET installed_at=installed_at WHERE version=?;")) {
                    lock.setInt(1, CURRENT_SCHEMA_VERSION);
                    lock.executeUpdate();
                }
                locked = true;
            } else {
                locked = acquireAdvisoryLock(c, "failures");
            }
            if (!locked) return failedFailureState();
            DataSource.FailureStateResult previous = selectFailureState(c, key);
            if (!previous.successful()) return previous;
            long windowStart = previous.windowStarted();
            int attempts = previous.attempts();
            long bannedUntil = previous.bannedUntil();
            if (windowStart <= 0L || now - windowStart > Math.max(1L, windowMillis)) {
                windowStart = now;
                attempts = 0;
                bannedUntil = 0L;
            }
            attempts++;
            if (banThreshold > 0 && attempts >= banThreshold && banMillis > 0L) {
                bannedUntil = Math.max(bannedUntil, now + banMillis);
            }
            int updated;
            String table = quote(securityStateTable());
            try (PreparedStatement update = c.prepareStatement("UPDATE " + table + " SET "
                + quote("attempts") + "=?," + quote("window_started") + "=?,"
                + quote("last_failure") + "=?," + quote("banned_until") + "=? WHERE "
                + quote("state_key") + "=?;")) {
                update.setInt(1, attempts);
                update.setLong(2, windowStart);
                update.setLong(3, now);
                update.setLong(4, bannedUntil);
                update.setString(5, key);
                updated = update.executeUpdate();
            }
            if (updated == 0) {
                try (PreparedStatement insert = c.prepareStatement("INSERT INTO " + table + " ("
                    + quote("state_key") + ',' + quote("attempts") + ',' + quote("window_started")
                    + ',' + quote("last_failure") + ',' + quote("banned_until")
                    + ") VALUES (?,?,?,?,?);")) {
                    insert.setString(1, key);
                    insert.setInt(2, attempts);
                    insert.setLong(3, windowStart);
                    insert.setLong(4, now);
                    insert.setLong(5, bannedUntil);
                    insert.executeUpdate();
                }
            }
            commitSqlite(c, sqliteTransaction);
            return new DataSource.FailureStateResult(
                attempts, windowStart, now, bannedUntil, true);
        } catch (SQLException exception) {
            rollbackSqlite(c, sqliteTransaction);
            Log.error("Could not record shared authentication failure state", exception);
            return failedFailureState();
        } finally {
            if (c != null && locked && !sqliteTransaction) releaseAdvisoryLock(c, "failures");
            if (c != null && sqliteTransaction) {
                try { c.setAutoCommit(true); } catch (SQLException ignored) { }
            }
            releaseConnection(c);
        }
    }

    @Override
    public boolean clearFailureState(String key) {
        if (key == null || key.isBlank() || key.length() > 191) return false;
        Connection c = null;
        boolean locked = false;
        boolean sqliteTransaction = false;
        try {
            c = borrowConnection();
            if (getType() == DataSourceType.SQLITE) {
                c.setAutoCommit(false);
                sqliteTransaction = true;
                try (PreparedStatement lock = c.prepareStatement("UPDATE "
                    + quote(settings.table + "_schema_history")
                    + " SET installed_at=installed_at WHERE version=?;")) {
                    lock.setInt(1, CURRENT_SCHEMA_VERSION);
                    lock.executeUpdate();
                }
                locked = true;
            } else {
                locked = acquireAdvisoryLock(c, "failures");
            }
            if (!locked) return false;
            try (PreparedStatement delete = c.prepareStatement("DELETE FROM "
                + quote(securityStateTable()) + " WHERE " + quote("state_key") + "=?;")) {
                delete.setString(1, key);
                delete.executeUpdate();
            }
            commitSqlite(c, sqliteTransaction);
            return true;
        } catch (SQLException exception) {
            rollbackSqlite(c, sqliteTransaction);
            Log.error("Could not clear shared authentication failure state", exception);
            return false;
        } finally {
            if (c != null && locked && !sqliteTransaction) releaseAdvisoryLock(c, "failures");
            if (c != null && sqliteTransaction) {
                try { c.setAutoCommit(true); } catch (SQLException ignored) { }
            }
            releaseConnection(c);
        }
    }

    private DataSource.FailureStateResult selectFailureState(Connection c, String key)
        throws SQLException {
        String sql = "SELECT " + quote("attempts") + ',' + quote("window_started") + ','
            + quote("last_failure") + ',' + quote("banned_until") + " FROM "
            + quote(securityStateTable()) + " WHERE " + quote("state_key") + "=?;";
        try (PreparedStatement select = c.prepareStatement(sql)) {
            select.setString(1, key);
            try (ResultSet rs = select.executeQuery()) {
                if (!rs.next()) return emptyFailureState();
                return new DataSource.FailureStateResult(rs.getInt(1), rs.getLong(2),
                    rs.getLong(3), rs.getLong(4), true);
            }
        }
    }

    private static DataSource.FailureStateResult emptyFailureState() {
        return new DataSource.FailureStateResult(0, 0L, 0L, 0L, true);
    }

    private static DataSource.FailureStateResult failedFailureState() {
        return new DataSource.FailureStateResult(0, 0L, 0L, 0L, false);
    }

    private DataSource.CountResult countWhere(String column, String value, String description) {
        String sql = "SELECT COUNT(*) FROM " + quote(settings.table) + " WHERE " + quote(column) + "=?;";
        return count(sql, value == null ? "" : value, description);
    }

    private DataSource.CountResult count(String sql, String value, String description) {
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setString(1, value);
                try (ResultSet rs = pst.executeQuery()) {
                    return new DataSource.CountResult(rs.next() ? rs.getInt(1) : 0, true);
                }
            }
        } catch (SQLException e) {
            Log.error("Could not count accounts by " + description, e);
            return new DataSource.CountResult(0, false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.QueryResult<List<PlayerAuth>> queryRecentAccounts(int limit) {
        List<PlayerAuth> accounts = new ArrayList<>();
        int safeLimit = Math.max(1, Math.min(100, limit));
        String sql = "SELECT * FROM " + quote(settings.table) + " ORDER BY "
            + quote(col.REGISTRATION_DATE) + " DESC LIMIT ?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setInt(1, safeLimit);
                try (ResultSet rs = pst.executeQuery()) {
                    while (rs.next()) accounts.add(buildAuthFromResultSet(rs));
                }
            }
            return new DataSource.QueryResult<>(accounts, true);
        } catch (SQLException e) {
            Log.error("Could not query recent accounts", e);
            return new DataSource.QueryResult<>(List.of(), false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.QueryResult<List<PlayerAuth>> queryPurgeCandidates(long cutoffMillis, int limit) {
        List<PlayerAuth> accounts = new ArrayList<>();
        int safeLimit = Math.max(1, Math.min(10000, limit));
        String lastActivity = "CASE WHEN COALESCE(" + quote(col.LAST_LOGIN) + ",0) > COALESCE("
            + quote(col.REGISTRATION_DATE) + ",0) THEN COALESCE(" + quote(col.LAST_LOGIN) + ",0) ELSE COALESCE("
            + quote(col.REGISTRATION_DATE) + ",0) END";
        String sql = "SELECT * FROM " + quote(settings.table) + " WHERE " + lastActivity
            + " < ? AND " + quote(col.IS_LOGGED) + "=0 AND NOT EXISTS (SELECT 1 FROM "
            + quote(loginLeaseTable()) + " lease_guard WHERE lease_guard." + quote("username")
            + "=" + quote(settings.table) + "." + quote(col.NAME) + " AND lease_guard."
            + quote("expires_at") + ">=?) ORDER BY " + lastActivity + " ASC LIMIT ?;";
        Connection c = null;
        try {
            c = borrowConnection();
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                pst.setLong(1, cutoffMillis);
                pst.setLong(2, System.currentTimeMillis());
                pst.setInt(3, safeLimit);
                try (ResultSet rs = pst.executeQuery()) {
                    while (rs.next()) accounts.add(buildAuthFromResultSet(rs));
                }
            }
            return new DataSource.QueryResult<>(accounts, true);
        } catch (SQLException e) {
            Log.error("Could not query old accounts before purge", e);
            return new DataSource.QueryResult<>(List.of(), false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.OperationResult purgeRegisteredBefore(long cutoffMillis, int limit) {
        int safeLimit = Math.max(1, Math.min(10000, limit));
        String lastActivity = "CASE WHEN COALESCE(" + quote(col.LAST_LOGIN) + ",0) > COALESCE("
            + quote(col.REGISTRATION_DATE) + ",0) THEN COALESCE(" + quote(col.LAST_LOGIN) + ",0) ELSE COALESCE("
            + quote(col.REGISTRATION_DATE) + ",0) END";
        String select = "SELECT " + quote(col.NAME) + " FROM " + quote(settings.table)
            + " WHERE " + lastActivity + " < ? AND " + quote(col.IS_LOGGED)
            + "=0 AND NOT EXISTS (SELECT 1 FROM " + quote(loginLeaseTable())
            + " lease_guard WHERE lease_guard." + quote("username") + "=" + quote(settings.table)
            + "." + quote(col.NAME) + " AND lease_guard." + quote("expires_at")
            + ">=?) ORDER BY " + lastActivity + " ASC LIMIT ?;";
        String delete = "DELETE FROM " + quote(settings.table) + " WHERE " + quote(col.NAME)
            + "=? AND " + lastActivity + " < ? AND " + quote(col.IS_LOGGED)
            + "=0 AND NOT EXISTS (SELECT 1 FROM " + quote(loginLeaseTable())
            + " lease_guard WHERE lease_guard." + quote("username") + "=" + quote(settings.table)
            + "." + quote(col.NAME) + " AND lease_guard." + quote("expires_at") + ">=?);";
        Connection c = null;
        try {
            c = borrowConnection();
            boolean oldAutoCommit = c.getAutoCommit();
            c.setAutoCommit(false);
            List<String> names = new ArrayList<>();
            try (PreparedStatement pst = c.prepareStatement(select)) {
                pst.setLong(1, cutoffMillis);
                pst.setLong(2, System.currentTimeMillis());
                pst.setInt(3, safeLimit);
                try (ResultSet rs = pst.executeQuery()) {
                    while (rs.next()) names.add(rs.getString(1));
                }
            }
            int affected = 0;
            try (PreparedStatement pst = c.prepareStatement(delete)) {
                for (String name : names) {
                    pst.setString(1, name);
                    pst.setLong(2, cutoffMillis);
                    pst.setLong(3, System.currentTimeMillis());
                    affected += pst.executeUpdate();
                }
            }
            c.commit();
            c.setAutoCommit(oldAutoCommit);
            return new DataSource.OperationResult(affected, true);
        } catch (SQLException e) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not purge old accounts", e);
            return new DataSource.OperationResult(0, false);
        } finally {
            releaseConnection(c);
        }
    }

    @Override
    public DataSource.OperationResult removeAuthIfUnchanged(PlayerAuth expected, long cutoffMillis) {
        if (expected == null || expected.getName() == null || expected.getName().isBlank()) {
            return new DataSource.OperationResult(0, false);
        }
        String lastActivity = "CASE WHEN COALESCE(" + quote(col.LAST_LOGIN) + ",0) > COALESCE("
            + quote(col.REGISTRATION_DATE) + ",0) THEN COALESCE(" + quote(col.LAST_LOGIN)
            + ",0) ELSE COALESCE(" + quote(col.REGISTRATION_DATE) + ",0) END";
        StringBuilder sql = new StringBuilder("DELETE FROM ").append(quote(settings.table))
            .append(" WHERE ").append(quote(col.NAME)).append("=? AND ").append(lastActivity)
            .append(" < ? AND ").append(quote(col.REGISTRATION_DATE)).append("=?");
        appendNullableSnapshotMatch(sql, col.LAST_LOGIN);
        appendNullableSnapshotMatch(sql, col.REAL_NAME);
        appendNullableSnapshotMatch(sql, col.PASSWORD);
        if (col.hasSaltColumn()) appendNullableSnapshotMatch(sql, col.SALT);
        appendNullableSnapshotMatch(sql, col.EMAIL);
        if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) {
            appendNullableSnapshotMatch(sql, col.TOTP_KEY);
        }
        if (col.hasPremiumUuidColumn()) appendNullableSnapshotMatch(sql, col.PREMIUM_UUID);
        if (col.hasPlayerUuidColumn()) appendNullableSnapshotMatch(sql, col.PLAYER_UUID);
        sql.append(" AND ").append(quote(col.IS_LOGGED))
            .append("=0 AND NOT EXISTS (SELECT 1 FROM ").append(quote(loginLeaseTable()))
            .append(" lease_guard WHERE lease_guard.").append(quote("username")).append('=')
            .append(quote(settings.table)).append('.').append(quote(col.NAME))
            .append(" AND lease_guard.").append(quote("expires_at")).append(">=?);");
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            int affected;
            try (PreparedStatement delete = c.prepareStatement(sql.toString())) {
                int index = 1;
                delete.setString(index++, expected.getName().toLowerCase(Locale.ROOT));
                delete.setLong(index++, cutoffMillis);
                delete.setLong(index++, expected.getRegistrationDate());
                if (expected.getLastLogin() == null) {
                    delete.setNull(index++, java.sql.Types.BIGINT);
                    delete.setNull(index++, java.sql.Types.BIGINT);
                } else {
                    delete.setLong(index++, expected.getLastLogin());
                    delete.setLong(index++, expected.getLastLogin());
                }
                index = setNullableSnapshotValue(delete, index, expected.getRealName());
                index = setNullableSnapshotValue(delete, index, expected.getHash());
                if (col.hasSaltColumn()) {
                    index = setNullableSnapshotValue(delete, index, expected.getSalt());
                }
                index = setNullableSnapshotValue(delete, index, expected.getEmail());
                if (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) {
                    index = setNullableSnapshotValue(delete, index, expected.getTotpKey());
                }
                if (col.hasPremiumUuidColumn()) {
                    index = setNullableSnapshotValue(delete, index,
                        expected.getPremiumUuid() == null ? null : expected.getPremiumUuid().toString());
                }
                if (col.hasPlayerUuidColumn()) {
                    index = setNullableSnapshotValue(delete, index,
                        expected.getUuid() == null ? null : expected.getUuid().toString());
                }
                delete.setLong(index, System.currentTimeMillis());
                affected = delete.executeUpdate();
            }
            if (affected > 0) deleteAllLoginLeases(c, expected.getName());
            c.commit();
            return new DataSource.OperationResult(affected, true);
        } catch (SQLException exception) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not conditionally purge account " + expected.getName(), exception);
            return new DataSource.OperationResult(0, false);
        } finally {
            releaseConnection(c);
        }
    }

    private void appendNullableSnapshotMatch(StringBuilder sql, String column) {
        sql.append(" AND ((").append(quote(column)).append("=?) OR (")
            .append(quote(column)).append(" IS NULL AND ? IS NULL))");
    }

    private static int setNullableSnapshotValue(PreparedStatement statement, int index, String value)
        throws SQLException {
        statement.setString(index++, value);
        statement.setString(index++, value);
        return index;
    }

    @Override
    public DataSource.OperationResult clearLoggedFlags() {
        String sql = "UPDATE " + quote(settings.table) + " SET " + quote(col.IS_LOGGED) + "=0, "
            + quote(col.HAS_SESSION) + "=0 WHERE " + quote(col.IS_LOGGED) + "<>0 OR "
            + quote(col.HAS_SESSION) + "<>0;";
        Connection c = null;
        try {
            c = borrowConnection();
            c.setAutoCommit(false);
            int affected;
            try (Statement st = c.createStatement()) {
                affected = st.executeUpdate(sql);
                st.executeUpdate("DELETE FROM " + quote(loginLeaseTable()) + ";");
            }
            c.commit();
            return new DataSource.OperationResult(affected, true);
        } catch (SQLException e) {
            if (c != null) try { c.rollback(); } catch (SQLException ignored) { }
            Log.error("Could not clear stale login flags", e);
            return new DataSource.OperationResult(0, false);
        } finally {
            releaseConnection(c);
        }
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
            if (settings.schemaMode == DbSettings.SchemaMode.MIGRATE) runVersionedMigrations();
            else {
                validateSchemaAndColumns();
                validateSecurityStateSchema();
                validateLoginLeaseSchema();
            }
        } catch (SQLException e) {
            Log.error("Could not validate/migrate schema after reload", e);
        }
    }

    @Override
    public void close() {
        pool.close();
    }

    @Override
    public boolean backup(Path destination) {
        if (destination == null) return false;
        Connection c = null;
        Path temporary = null;
        try {
            Path absolute = destination.toAbsolutePath().normalize();
            Path parent = absolute.getParent();
            if (parent == null || Files.isSymbolicLink(parent)
                || (Files.exists(parent, LinkOption.NOFOLLOW_LINKS)
                    && !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS))) return false;
            Files.createDirectories(parent);
            if (Files.isSymbolicLink(absolute)) return false;
            temporary = SecureFileAccess.createPrivateTempFile(parent,
                absolute.getFileName().toString() + ".", ".tmp");
            c = borrowConnection();
            try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT * FROM " + quote(settings.table) + ";");
                 BufferedWriter out = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8,
                     java.nio.file.StandardOpenOption.WRITE,
                     java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                     LinkOption.NOFOLLOW_LINKS)) {
                var meta = rs.getMetaData();
                out.write("-- AuthMe Fabric logical backup for table " + settings.table + System.lineSeparator());
                out.write("-- Generated at " + java.time.Instant.now() + System.lineSeparator());
                while (rs.next()) {
                    out.write("INSERT INTO " + quote(settings.table) + " (");
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        if (i > 1) out.write(", ");
                        out.write(quote(meta.getColumnName(i)));
                    }
                    out.write(") VALUES (");
                    for (int i = 1; i <= meta.getColumnCount(); i++) {
                        if (i > 1) out.write(", ");
                        writeSqlLiteral(out, rs.getObject(i));
                    }
                    out.write(");");
                    out.newLine();
                }
            }
            SecureFileAccess.replace(temporary, absolute);
            temporary = null;
            return true;
        } catch (SQLException | IOException e) {
            Log.error("Could not create database backup at " + destination, e);
            return false;
        } finally {
            releaseConnection(c);
            if (temporary != null) {
                try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
            }
        }
    }

    @Override
    public DataSource.MySqlDefinitionResult mysqlDefinition(
        DataSource.MySqlDefinitionOperation operation, String requestedColumn) {
        if (getType() != DataSourceType.MYSQL && getType() != DataSourceType.MARIADB) {
            return DataSource.MySqlDefinitionResult.unsupported(
                "This operation is available for MySQL/MariaDB only.");
        }
        if (operation == null) {
            return DataSource.MySqlDefinitionResult.failure("A mysqldef operation is required.");
        }
        try {
            if (operation == DataSource.MySqlDefinitionOperation.DETAILS) {
                return DataSource.MySqlDefinitionResult.success(readMySqlDefinitionDetails());
            }
            MySqlDefinitionColumn column = MySqlDefinitionColumn.from(requestedColumn);
            if (column == null) {
                return DataSource.MySqlDefinitionResult.failure(
                    "Column must be LASTLOGIN, LASTIP or EMAIL.");
            }
            return changeMySqlDefinition(operation, column);
        } catch (SQLException | IllegalArgumentException exception) {
            // The operator-facing result is intentionally generic. The detailed exception is
            // logged locally, but a JDBC URL, driver diagnostic or server metadata must not be
            // sent to a command sender.
            Log.error("Could not execute AuthMe mysqldef operation", exception);
            return DataSource.MySqlDefinitionResult.failure("Database operation failed; see the server log.");
        }
    }

    private DataSource.MySqlDefinitionResult changeMySqlDefinition(
        DataSource.MySqlDefinitionOperation operation, MySqlDefinitionColumn column) throws SQLException {
        String table = quote(settings.table);
        String name = quote(column.name(col));
        Connection connection = null;
        try {
            connection = borrowConnection();
            List<String> lines = new ArrayList<>();
            if (operation == DataSource.MySqlDefinitionOperation.ADD) {
                int updated;
                String update = "UPDATE " + table + " SET " + name + "=? WHERE " + name + " IS NULL;";
                try (PreparedStatement statement = connection.prepareStatement(update)) {
                    column.bindDefault(statement, 1);
                    updated = statement.executeUpdate();
                }
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER TABLE " + table + " MODIFY " + name + " "
                        + column.notNullDefinition());
                }
                lines.add("Replaced NULLs with default value for " + column.name()
                    + ": " + updated + " row(s).");
                lines.add("Changed " + column.name() + " (" + column.configuredName(col)
                    + ") to NOT NULL with a default.");
            } else if (operation == DataSource.MySqlDefinitionOperation.REMOVE) {
                try (Statement statement = connection.createStatement()) {
                    statement.execute("ALTER TABLE " + table + " MODIFY " + name + " "
                        + column.nullableDefinition());
                }
                int updated;
                String update = "UPDATE " + table + " SET " + name + "=NULL WHERE " + name + "=?;";
                try (PreparedStatement statement = connection.prepareStatement(update)) {
                    column.bindDefault(statement, 1);
                    updated = statement.executeUpdate();
                }
                lines.add("Changed " + column.name() + " (" + column.configuredName(col)
                    + ") to allow NULL.");
                lines.add("Replaced the old default value with NULL: " + updated + " row(s).");
            } else {
                return DataSource.MySqlDefinitionResult.failure("Unsupported mysqldef operation.");
            }
            return DataSource.MySqlDefinitionResult.success(lines);
        } finally {
            releaseConnection(connection);
        }
    }

    private List<String> readMySqlDefinitionDetails() throws SQLException {
        List<String> lines = new ArrayList<>();
        Connection connection = null;
        try {
            connection = borrowConnection();
            DatabaseMetaData metadata = connection.getMetaData();
            for (MySqlDefinitionColumn column : MySqlDefinitionColumn.values()) {
                ColumnMetadata detail = readColumnMetadata(metadata, column.configuredName(col));
                if (detail == null) {
                    lines.add(column.name() + " (" + column.configuredName(col) + "): column not found");
                } else {
                    String nullable = detail.nullable() ? "nullable" : "NOT NULL";
                    String defaultValue = detail.defaultValue() == null
                        ? "no default" : "default='" + detail.defaultValue() + "'";
                    lines.add(column.name() + " (" + column.configuredName(col) + "): "
                        + detail.type() + ", " + nullable + ", " + defaultValue);
                }
            }
            return lines;
        } finally {
            releaseConnection(connection);
        }
    }

    private ColumnMetadata readColumnMetadata(DatabaseMetaData metadata, String column) throws SQLException {
        String catalog = settings.database == null || settings.database.isBlank() ? null : settings.database;
        try (ResultSet result = metadata.getColumns(catalog, null, settings.table, column)) {
            if (result.next()) return columnMetadata(result);
        }
        // Some MySQL/MariaDB drivers expose the database as a schema instead of a catalog.
        try (ResultSet result = metadata.getColumns(null, catalog, settings.table, column)) {
            if (result.next()) return columnMetadata(result);
        }
        return null;
    }

    private static ColumnMetadata columnMetadata(ResultSet result) throws SQLException {
        String nullableValue = result.getString("IS_NULLABLE");
        boolean nullable = "YES".equalsIgnoreCase(nullableValue);
        return new ColumnMetadata(nullable, result.getString("COLUMN_DEF"), result.getString("TYPE_NAME"));
    }

    private enum MySqlDefinitionColumn {
        LASTLOGIN("BIGINT", "BIGINT NOT NULL DEFAULT 0", 0L),
        LASTIP("VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin",
            "VARCHAR(40) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT '127.0.0.1'",
            "127.0.0.1"),
        EMAIL("VARCHAR(255)", "VARCHAR(255) NOT NULL DEFAULT 'your@email.com'", "your@email.com");

        private final String nullableDefinition;
        private final String notNullDefinition;
        private final Object defaultValue;

        MySqlDefinitionColumn(String nullableDefinition, String notNullDefinition, Object defaultValue) {
            this.nullableDefinition = nullableDefinition;
            this.notNullDefinition = notNullDefinition;
            this.defaultValue = defaultValue;
        }

        static MySqlDefinitionColumn from(String value) {
            if (value == null) return null;
            try {
                return valueOf(value.trim().toUpperCase(Locale.ROOT));
            } catch (IllegalArgumentException exception) {
                return null;
            }
        }

        String name(Columns columns) {
            return switch (this) {
                case LASTLOGIN -> columns.LAST_LOGIN;
                case LASTIP -> columns.LAST_IP;
                case EMAIL -> columns.EMAIL;
            };
        }

        String configuredName(Columns columns) { return name(columns); }

        String nullableDefinition() { return nullableDefinition; }
        String notNullDefinition() { return notNullDefinition; }

        void bindDefault(PreparedStatement statement, int index) throws SQLException {
            if (defaultValue instanceof Long value) statement.setLong(index, value);
            else statement.setString(index, String.valueOf(defaultValue));
        }
    }

    private record ColumnMetadata(boolean nullable, String defaultValue, String type) { }

    private static void writeSqlLiteral(BufferedWriter out, Object value) throws IOException {
        if (value == null) {
            out.write("NULL");
        } else if (value instanceof Number || value instanceof Boolean) {
            out.write(String.valueOf(value));
        } else if (value instanceof byte[] bytes) {
            out.write("X'");
            for (byte b : bytes) out.write(String.format("%02x", b & 0xff));
            out.write("'");
        } else {
            out.write("'");
            out.write(String.valueOf(value).replace("'", "''"));
            out.write("'");
        }
    }

    // ---------------------------------------------------------------- helpers

    protected PlayerAuth buildAuthFromResultSet(ResultSet rs) throws SQLException {
        String salt = col.hasSaltColumn() ? rs.getString(col.SALT) : null;
        UUID uuid = col.hasPlayerUuidColumn() ? parseUuidSafely(rs.getString(col.PLAYER_UUID)) : null;
        UUID premiumUuid = col.hasPremiumUuidColumn() ? parseUuidSafely(rs.getString(col.PREMIUM_UUID)) : null;
        Long lastLogin = getNullableLong(rs, col.LAST_LOGIN);
        String totp = (col.TOTP_KEY != null && !col.TOTP_KEY.isEmpty()) ? rs.getString(col.TOTP_KEY) : null;
        return PlayerAuth.builder()
            .id(safeInt(rs, col.ID))
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
            .logged(safeBoolean(rs, col.IS_LOGGED))
            .hasSession(safeBoolean(rs, col.HAS_SESSION))
            .uuid(uuid)
            .premiumUuid(premiumUuid)
            .build();
    }

    private static int safeInt(ResultSet rs, String column) throws SQLException {
        try { return rs.getInt(column); } catch (SQLException e) { return 0; }
    }

    private static boolean safeBoolean(ResultSet rs, String column) throws SQLException {
        try { return rs.getBoolean(column); } catch (SQLException e) { return false; }
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
        if (identifier == null || !identifier.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid SQL identifier");
        }
        return identifier;
    }

    @FunctionalInterface
    private interface StatementBinder {
        void bind(PreparedStatement statement) throws SQLException;
    }

    private boolean inTransaction(String sql, StatementBinder binder, String user) {
        Connection c = null;
        try {
            c = borrowConnection();
            boolean previousAutoCommit = c.getAutoCommit();
            c.setAutoCommit(false);
            try (PreparedStatement pst = c.prepareStatement(sql)) {
                binder.bind(pst);
                if (pst.executeUpdate() != 1) {
                    c.rollback();
                    c.setAutoCommit(previousAutoCommit);
                    return false;
                }
                c.commit();
                c.setAutoCommit(previousAutoCommit);
                return true;
            } catch (SQLException e) {
                try { c.rollback(); } catch (SQLException ignored) { }
                try { c.setAutoCommit(previousAutoCommit); } catch (SQLException ignored) { }
                throw e;
            }
        } catch (SQLException e) {
            Log.error("Could not atomically update login state for " + user, e);
            return false;
        } finally {
            releaseConnection(c);
        }
    }

    /**
     * Column/table names are configuration values and are interpolated into DDL by the backend
     * implementations. Restricting them to ordinary SQL identifiers makes that interpolation safe
     * and avoids turning a malformed config into an injected statement.
     */
    private void validateIdentifiers() throws SQLException {
        if (settings == null || col == null) throw new SQLException("Database settings are incomplete");
        validateIdentifier(settings.table, "table");
        String[] required = {
            col.NAME, col.REAL_NAME, col.PASSWORD, col.LAST_IP, col.LAST_LOGIN,
            col.LASTLOC_X, col.LASTLOC_Y, col.LASTLOC_Z, col.LASTLOC_WORLD,
            col.LASTLOC_YAW, col.LASTLOC_PITCH, col.EMAIL, col.ID, col.IS_LOGGED,
            col.HAS_SESSION, col.REGISTRATION_DATE, col.REGISTRATION_IP
        };
        for (String identifier : required) validateIdentifier(identifier, "column");
        String[] identifiers = {
            col.SALT, col.TOTP_KEY, col.GROUP, col.PLAYER_UUID, col.PREMIUM_UUID
        };
        for (String identifier : identifiers) {
            if (identifier != null && !identifier.isEmpty()) validateIdentifier(identifier, "column");
        }
    }

    private static void validateIdentifier(String identifier, String kind) throws SQLException {
        int maximum = "table".equals(kind) ? 48 : 63;
        if (identifier == null || identifier.length() > maximum
            || !identifier.matches("[A-Za-z_][A-Za-z0-9_]*")) {
            throw new SQLException("Invalid " + kind + " name; use at most " + maximum
                + " letters, digits or underscores and start with a letter/underscore");
        }
    }
}
