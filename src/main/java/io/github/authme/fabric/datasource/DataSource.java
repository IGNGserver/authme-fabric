package io.github.authme.fabric.datasource;

import io.github.authme.fabric.security.HashedPassword;

import java.util.List;
import java.util.UUID;

/**
 * AuthMe account data source. Operations mirror the subset of AuthMe's
 * {@code fr.xephi.authme.datasource.DataSource} that is needed for account registration, login,
 * session support and 2FA, so this port interoperates with a database owned by the original plugin.
 */
public interface DataSource {

    PlayerAuth getAuth(String user);

    boolean isAuthAvailable(String user);

    boolean saveAuth(PlayerAuth auth);

    boolean updatePassword(String user, HashedPassword password);

    boolean updateRealName(String user, String realName);

    boolean setLogged(String user, boolean logged);

    boolean setSession(String user, boolean hasSession);

    boolean updateIp(String user, String ip);

    boolean updateLastLogin(String user, long lastLogin);

    boolean updateEmail(String user, String email);

    boolean updateTotpKey(String user, String totpKey);

    boolean updatePremiumUuid(String user, UUID premiumUuid);

    boolean updateLocation(String user, double x, double y, double z, float yaw, float pitch, String world);

    boolean removeAuth(String user);

    int countAuths();

    List<String> getRegisteredNames();

    List<String> getLoggedPlayersWithEmptyMail();

    boolean isLogged(String user);

    void reload();

    void close();

    DataSourceType getType();

    Columns getColumns();
}