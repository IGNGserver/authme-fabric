package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;

import java.util.List;
import java.nio.file.Path;
import java.util.UUID;

/**
 * AuthMe account data source. Operations mirror the subset of AuthMe's
 * {@code fr.xephi.authme.datasource.DataSource} that is needed for account registration, login,
 * session support and 2FA, so this port interoperates with a database owned by the original plugin.
 */
public interface DataSource {

    PlayerAuth getAuth(String user);

    /** Performs a lookup while preserving the distinction between “not found” and “database error”. */
    default LookupResult lookupAuth(String user) {
        return new LookupResult(getAuth(user), true);
    }

    /** Looks up an account by its configured e-mail column. */
    default PlayerAuth getAuthByEmail(String email) {
        return null;
    }

    boolean isAuthAvailable(String user);

    /** Performs an availability check while preserving database failures. */
    default CheckResult checkAuthAvailable(String user) {
        return new CheckResult(isAuthAvailable(user), true);
    }

    boolean saveAuth(PlayerAuth auth);

    boolean updatePassword(String user, HashedPassword password);

    /**
     * Replaces a password only when the row still contains {@code expected}. This compare-and-set
     * operation is used by legacy-hash migration so two AuthMe instances cannot overwrite a newer
     * password change with a delayed rehash.
     *
     * <p>Adapters which cannot provide an atomic compare-and-set must return {@code false}; a
     * caller must never silently fall back to an unconditional password write.</p>
     */
    default boolean updatePasswordIfMatches(String user, HashedPassword expected,
                                            HashedPassword replacement) {
        return false;
    }

    /**
     * Changes a password and invalidates both login/session flags in one database transaction.
     * Password recovery uses this transition so a successful reset can never leave the old
     * authenticated state active when the second write fails.
     */
    boolean updatePasswordAndClearLogin(String user, HashedPassword password);

    boolean updateRealName(String user, String realName);

    boolean setLogged(String user, boolean logged);

    boolean setSession(String user, boolean hasSession);

    /** Persists the complete successful-login state atomically when the backend supports it. */
    default boolean setLoginState(String user, String ip, long lastLogin, boolean hasSession) {
        return setLogged(user, true)
            && updateIp(user, ip)
            && updateLastLogin(user, lastLogin)
            && setSession(user, hasSession);
    }

    /**
     * Acquires a fenced login lease and enforces the per-IP quota under one database-wide
     * coordination lock. The returned version must be retained by the live connection.
     */
    default LoginStateResult acquireLoginState(String user, String ip, long requestedVersion,
                                               boolean hasSession, int maxLoggedPerIp) {
        boolean saved = setLoginState(user, ip, requestedVersion, hasSession);
        return saved ? new LoginStateResult(LoginStateStatus.ACQUIRED, requestedVersion)
            : new LoginStateResult(LoginStateStatus.ERROR, 0L);
    }

    /** Renews and validates a cross-instance login lease owned by one live connection. */
    default LoginLeaseResult renewLoginLease(String user, long version, long now) {
        LookupResult current = lookupAuth(user);
        if (!current.successful()) return new LoginLeaseResult(false, false);
        PlayerAuth auth = current.auth();
        boolean active = auth != null && auth.isLogged() && auth.getLastLogin() != null
            && auth.getLastLogin() == version;
        return new LoginLeaseResult(active, true);
    }

    /** Persists logout flags atomically when the backend supports it. */
    default boolean setLoginFlags(String user, boolean logged, boolean hasSession) {
        return setLogged(user, logged) && setSession(user, hasSession);
    }

    /** Persists disconnect timestamp/location and clears login flags as one state transition. */
    default boolean persistDisconnect(String user, long lastLogin, double x, double y, double z,
                                      float yaw, float pitch, String world, boolean saveLocation,
                                      boolean keepSession) {
        boolean ok = updateLastLogin(user, lastLogin);
        if (saveLocation) ok &= updateLocation(user, x, y, z, yaw, pitch, world);
        ok &= setLoginFlags(user, false, keepSession);
        return ok;
    }

    /**
     * Persists a disconnect only if the account still has the login timestamp owned by this
     * connection. A stale disconnect becomes a successful no-op, so a rapid reconnect cannot be
     * logged out by the previous connection's delayed worker.
     */
    default boolean persistDisconnectIfLastLogin(String user, long expectedLastLogin, long lastLogin,
                                                  double x, double y, double z, float yaw, float pitch,
                                                  String world, boolean saveLocation, boolean keepSession) {
        LookupResult current = lookupAuth(user);
        if (!current.successful() || current.auth() == null) return false;
        Long stored = current.auth().getLastLogin();
        if (stored == null || stored != expectedLastLogin) return true;
        return persistDisconnect(user, lastLogin, x, y, z, yaw, pitch, world, saveLocation, keepSession);
    }

    /** Clears a stale login write only when it still owns the expected login timestamp. */
    default boolean clearLoginIfLastLogin(String user, long expectedLastLogin) {
        LookupResult current = lookupAuth(user);
        if (!current.successful() || current.auth() == null) return false;
        Long stored = current.auth().getLastLogin();
        if (stored == null || stored != expectedLastLogin) return true;
        return setLoginFlags(user, false, false);
    }

    boolean updateIp(String user, String ip);

    boolean updateLastLogin(String user, long lastLogin);

    boolean updateEmail(String user, String email);

    boolean updateTotpKey(String user, String totpKey);

    boolean updatePremiumUuid(String user, UUID premiumUuid);

    boolean updateLocation(String user, double x, double y, double z, float yaw, float pitch, String world);

    /** Clears the stored last-location fields for every account when the backend supports it. */
    default boolean resetAllLocations() { return false; }

    boolean removeAuth(String user);

    int countAuths();

    /** Performs a cheap connection/schema health check without changing account state. */
    default boolean ping() {
        return true;
    }

    List<String> getRegisteredNames();

    /** Returns accounts whose last authenticated address matches. The result keeps database failure distinct. */
    default QueryResult<List<String>> queryRegisteredNamesByIp(String ip) {
        return new QueryResult<>(List.of(), true);
    }

    /** Counts registrations from an address. A failed query must never be treated as zero by callers. */
    default CountResult countRegisteredByIp(String ip) {
        return new CountResult(0, true);
    }

    /** Counts currently authenticated accounts whose last address matches. */
    default CountResult countLoggedByIp(String ip) {
        return new CountResult(0, true);
    }

    /** Counts accounts using an e-mail address. */
    default CountResult countRegisteredByEmail(String email) {
        return new CountResult(0, true);
    }

    /** Returns premium account names for a proxy full-state resynchronization. */
    default QueryResult<List<String>> queryPremiumUsernames() {
        return new QueryResult<>(List.of(), true);
    }

    /** Checks the authoritative Premium UUID column without loading password/account secrets. */
    default CheckResult checkPremiumUsername(String user) {
        LookupResult lookup = lookupAuth(user);
        return new CheckResult(lookup.auth() != null && lookup.auth().getPremiumUuid() != null,
            lookup.successful());
    }

    /** Reads a shared password/TOTP failure bucket. */
    default FailureStateResult readFailureState(String key, long now, long windowMillis) {
        return new FailureStateResult(0, 0L, 0L, 0L, false);
    }

    /** Atomically increments a shared failure bucket and applies a configured temporary ban. */
    default FailureStateResult recordFailureState(String key, long now, long windowMillis,
                                                  int banThreshold, long banMillis) {
        return new FailureStateResult(0, 0L, 0L, 0L, false);
    }

    /** Removes a shared failure bucket after successful authentication/CAPTCHA. */
    default boolean clearFailureState(String key) { return false; }

    /** Returns the most recently registered accounts for administration/diagnostics. */
    default QueryResult<List<PlayerAuth>> queryRecentAccounts(int limit) {
        return new QueryResult<>(List.of(), true);
    }

    /** Returns the full records which are about to be removed by an old-account purge. */
    default QueryResult<List<PlayerAuth>> queryPurgeCandidates(long cutoffMillis, int limit) {
        return new QueryResult<>(List.of(), true);
    }

    /** Removes old records in a bounded operation. */
    default OperationResult purgeRegisteredBefore(long cutoffMillis, int limit) {
        return new OperationResult(0, true);
    }

    /**
     * Deletes one purge candidate only if its security-relevant snapshot is still current, its
     * activity remains older than the cutoff, and it has no live login lease. A changed candidate
     * is a successful no-op rather than a database failure.
     */
    default OperationResult removeAuthIfUnchanged(PlayerAuth expected, long cutoffMillis) {
        return new OperationResult(0, false);
    }

    /** Clears stale login/session flags after a controlled restart or maintenance operation. */
    default OperationResult clearLoggedFlags() {
        return new OperationResult(0, true);
    }

    List<String> getLoggedPlayersWithEmptyMail();

    boolean isLogged(String user);

    void reload();

    void close();

    DataSourceType getType();

    Columns getColumns();

    /** Writes a portable SQL snapshot or a backend-native backup to {@code destination}. */
    boolean backup(Path destination);

    /**
     * Implements AuthMe's operator-only MySQL nullable/default-column utility.
     * Non-MySQL data sources deliberately return an unsupported result instead of
     * attempting backend-specific DDL.
     */
    default MySqlDefinitionResult mysqlDefinition(MySqlDefinitionOperation operation, String column) {
        return MySqlDefinitionResult.unsupported("This operation is available for MySQL/MariaDB only.");
    }

    record LookupResult(PlayerAuth auth, boolean successful) { }

    record CheckResult(boolean available, boolean successful) { }

    record CountResult(int count, boolean successful) { }

    enum LoginStateStatus { ACQUIRED, LIMIT_REACHED, ERROR }

    record LoginStateResult(LoginStateStatus status, long version) {
        public boolean acquired() { return status == LoginStateStatus.ACQUIRED; }
    }

    record LoginLeaseResult(boolean active, boolean successful) { }

    record FailureStateResult(int attempts, long windowStarted, long lastFailure,
                              long bannedUntil, boolean successful) { }

    record OperationResult(int affected, boolean successful) { }

    record QueryResult<T>(T value, boolean successful) { }

    enum MySqlDefinitionOperation {
        ADD, REMOVE, DETAILS
    }

    /** Result deliberately contains display-safe lines, never JDBC URLs or credentials. */
    record MySqlDefinitionResult(boolean supported, boolean successful, List<String> lines, String error) {
        public MySqlDefinitionResult {
            lines = lines == null ? List.of() : List.copyOf(lines);
            error = error == null ? "" : error;
        }

        public static MySqlDefinitionResult unsupported(String message) {
            return new MySqlDefinitionResult(false, false, List.of(), message);
        }

        public static MySqlDefinitionResult failure(String message) {
            return new MySqlDefinitionResult(true, false, List.of(), message);
        }

        public static MySqlDefinitionResult success(List<String> lines) {
            return new MySqlDefinitionResult(true, true, lines, "");
        }
    }
}
