package io.github.authme.proxy.core;

import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.ReadOnlyDataSources;

import java.sql.SQLException;

/** Authoritative, pre-login Premium account lookup backed by the shared AuthMe schema. */
public final class PremiumDirectory implements AutoCloseable {

    public enum Decision {
        PREMIUM,
        NON_PREMIUM,
        UNAVAILABLE
    }

    private final boolean enabled;
    private final DataSource source;

    private PremiumDirectory(boolean enabled, DataSource source) {
        this.enabled = enabled;
        this.source = source;
    }

    /**
     * Opens and validates the directory before a proxy configuration becomes active. A Premium
     * configuration is rejected unless the existing table and Premium column can be queried.
     */
    public static PremiumDirectory open(ProxyConfig config) {
        if (!config.premiumEnabled()) return new PremiumDirectory(false, null);
        DataSource opened = null;
        try {
            opened = ReadOnlyDataSources.open(config.premiumDatabase());
            if (!opened.ping()
                || !opened.checkPremiumUsername("authme_schema_probe").successful()) {
                throw new SQLException("Premium database schema/column validation failed");
            }
            return new PremiumDirectory(true, opened);
        } catch (SQLException | RuntimeException exception) {
            if (opened != null) opened.close();
            throw new IllegalStateException(
                "Could not open the authoritative Premium directory with read-only access", exception);
        }
    }

    public boolean enabled() {
        return enabled;
    }

    /** Performs a fresh database check so cold starts and backend-message delays cannot weaken it. */
    public Decision check(String username) {
        if (!enabled) return Decision.NON_PREMIUM;
        DataSource.CheckResult result = source.checkPremiumUsername(username);
        if (!result.successful()) return Decision.UNAVAILABLE;
        return result.available() ? Decision.PREMIUM : Decision.NON_PREMIUM;
    }

    @Override
    public void close() {
        if (source != null) source.close();
    }
}
