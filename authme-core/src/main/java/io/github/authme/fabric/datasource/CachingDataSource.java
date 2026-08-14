package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;

import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AuthMe-compatible account cache.  Only successful database lookups are
 * cached; failures are never cached and therefore cannot turn a transient DB
 * outage into an authentication decision.  Every write invalidates the local
 * entry, while expiry bounds staleness for shared-database/proxy deployments.
 */
public final class CachingDataSource implements DataSource {

    private final DataSource source;
    private final long refreshMillis;
    private final long expireMillis;
    private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<>();

    public CachingDataSource(DataSource source, long refreshMillis, long expireMillis) {
        this.source = source;
        this.refreshMillis = Math.max(1_000L, refreshMillis);
        this.expireMillis = Math.max(this.refreshMillis, expireMillis);
    }

    public DataSource source() { return source; }
    public int cachedEntries() { purgeExpired(); return cache.size(); }

    @Override
    public LookupResult lookupAuth(String user) {
        String key = key(user);
        Entry entry = cache.get(key);
        long now = System.currentTimeMillis();
        if (entry != null && now - entry.createdAt <= refreshMillis) {
            // Refresh asynchronously is intentionally not used here: the
            // caller may be on the login worker and a stale hit is bounded by
            // the short refresh window, while a single request remains stable.
            return new LookupResult(entry.auth, true);
        }
        LookupResult result = source.lookupAuth(key);
        if (result.successful()) cache.put(key, new Entry(result.auth(), now));
        return result;
    }

    @Override
    public PlayerAuth getAuth(String user) { return lookupAuth(user).auth(); }

    @Override
    public PlayerAuth getAuthByEmail(String email) {
        PlayerAuth auth = source.getAuthByEmail(email);
        if (auth != null) cache.put(key(auth.getName()), new Entry(auth, System.currentTimeMillis()));
        return auth;
    }

    @Override
    public boolean isAuthAvailable(String user) { return checkAuthAvailable(user).available(); }

    @Override
    public CheckResult checkAuthAvailable(String user) {
        LookupResult lookup = lookupAuth(user);
        return new CheckResult(lookup.auth() != null, lookup.successful());
    }

    @Override public boolean saveAuth(PlayerAuth auth) { boolean ok = source.saveAuth(auth); if (ok) put(auth); return ok; }
    @Override public boolean updatePassword(String user, HashedPassword password) { return write(user, () -> source.updatePassword(user, password)); }
    @Override public boolean updateRealName(String user, String realName) { return write(user, () -> source.updateRealName(user, realName)); }
    @Override public boolean setLogged(String user, boolean logged) { return write(user, () -> source.setLogged(user, logged)); }
    @Override public boolean setSession(String user, boolean hasSession) { return write(user, () -> source.setSession(user, hasSession)); }
    @Override public boolean setLoginState(String user, String ip, long lastLogin, boolean hasSession) { return write(user, () -> source.setLoginState(user, ip, lastLogin, hasSession)); }
    @Override public boolean setLoginFlags(String user, boolean logged, boolean hasSession) { return write(user, () -> source.setLoginFlags(user, logged, hasSession)); }
    @Override public boolean persistDisconnect(String user, long lastLogin, double x, double y, double z, float yaw, float pitch, String world, boolean saveLocation, boolean keepSession) { return write(user, () -> source.persistDisconnect(user, lastLogin, x, y, z, yaw, pitch, world, saveLocation, keepSession)); }
    @Override public boolean updateIp(String user, String ip) { return write(user, () -> source.updateIp(user, ip)); }
    @Override public boolean updateLastLogin(String user, long lastLogin) { return write(user, () -> source.updateLastLogin(user, lastLogin)); }
    @Override public boolean updateEmail(String user, String email) { return write(user, () -> source.updateEmail(user, email)); }
    @Override public boolean updateTotpKey(String user, String totpKey) { return write(user, () -> source.updateTotpKey(user, totpKey)); }
    @Override public boolean updatePremiumUuid(String user, UUID premiumUuid) { return write(user, () -> source.updatePremiumUuid(user, premiumUuid)); }
    @Override public boolean updateLocation(String user, double x, double y, double z, float yaw, float pitch, String world) { return write(user, () -> source.updateLocation(user, x, y, z, yaw, pitch, world)); }
    @Override public boolean resetAllLocations() { boolean ok = source.resetAllLocations(); if (ok) cache.clear(); return ok; }

    @Override
    public boolean removeAuth(String user) {
        boolean ok = source.removeAuth(user);
        if (ok) cache.remove(key(user));
        return ok;
    }

    @Override public int countAuths() { return source.countAuths(); }
    @Override public boolean ping() { return source.ping(); }
    @Override public List<String> getRegisteredNames() { return source.getRegisteredNames(); }
    @Override public QueryResult<List<String>> queryRegisteredNamesByIp(String ip) { return source.queryRegisteredNamesByIp(ip); }
    @Override public CountResult countRegisteredByIp(String ip) { return source.countRegisteredByIp(ip); }
    @Override public CountResult countRegisteredByEmail(String email) { return source.countRegisteredByEmail(email); }
    @Override public QueryResult<List<String>> queryPremiumUsernames() { return source.queryPremiumUsernames(); }
    @Override public QueryResult<List<PlayerAuth>> queryRecentAccounts(int limit) { return source.queryRecentAccounts(limit); }
    @Override public QueryResult<List<PlayerAuth>> queryPurgeCandidates(long cutoffMillis, int limit) { return source.queryPurgeCandidates(cutoffMillis, limit); }

    @Override
    public OperationResult purgeRegisteredBefore(long cutoffMillis, int limit) {
        OperationResult result = source.purgeRegisteredBefore(cutoffMillis, limit);
        if (result.successful()) cache.clear();
        return result;
    }

    @Override
    public OperationResult clearLoggedFlags() {
        OperationResult result = source.clearLoggedFlags();
        if (result.successful()) cache.clear();
        return result;
    }

    @Override public List<String> getLoggedPlayersWithEmptyMail() { return source.getLoggedPlayersWithEmptyMail(); }
    @Override public boolean isLogged(String user) { return source.isLogged(user); }
    @Override public void reload() { cache.clear(); source.reload(); }
    @Override public void close() { cache.clear(); source.close(); }
    @Override public DataSourceType getType() { return source.getType(); }
    @Override public Columns getColumns() { return source.getColumns(); }
    @Override public boolean backup(Path destination) { return source.backup(destination); }

    private boolean write(String user, BooleanOperation operation) {
        boolean ok = operation.run();
        if (ok) invalidate(user);
        return ok;
    }

    private void put(PlayerAuth auth) {
        if (auth != null && auth.getName() != null) cache.put(key(auth.getName()), new Entry(auth, System.currentTimeMillis()));
    }

    private void invalidate(String user) { if (user != null) cache.remove(key(user)); }
    private static String key(String user) { return user == null ? "" : user.toLowerCase(Locale.ROOT); }

    private void purgeExpired() {
        long now = System.currentTimeMillis();
        cache.entrySet().removeIf(e -> now - e.getValue().createdAt > expireMillis);
    }

    @FunctionalInterface private interface BooleanOperation { boolean run(); }
    private record Entry(PlayerAuth auth, long createdAt) { }
}
