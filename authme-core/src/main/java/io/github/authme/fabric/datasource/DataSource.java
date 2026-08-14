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

    /** Returns accounts registered from an address. The result keeps database failure distinct. */
    default QueryResult<List<String>> queryRegisteredNamesByIp(String ip) {
        return new QueryResult<>(List.of(), true);
    }

    /** Counts registrations from an address. A failed query must never be treated as zero by callers. */
    default CountResult countRegisteredByIp(String ip) {
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

    record LookupResult(PlayerAuth auth, boolean successful) { }

    record CheckResult(boolean available, boolean successful) { }

    record CountResult(int count, boolean successful) { }

    record OperationResult(int affected, boolean successful) { }

    record QueryResult<T>(T value, boolean successful) { }
}
