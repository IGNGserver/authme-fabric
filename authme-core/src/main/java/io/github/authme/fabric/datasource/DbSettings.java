package io.github.authme.fabric.datasource;

/**
 * Resolved database settings passed to a {@link DataSource} implementation.
 */
public final class DbSettings {

    public final DataSourceType backend;
    public final String host;
    public final String port;
    public final String user;
    public final String password;
    public final String database;
    public final String table;
    public final int poolSize;
    public final int maxLifetimeSeconds;
    public final boolean useSsl;
    public final boolean checkServerCertificate;
    public final boolean allowPublicKeyRetrieval;
    public final Columns columns;

    public DbSettings(DataSourceType backend, String host, String port, String user, String password,
                      String database, String table, int poolSize, int maxLifetimeSeconds,
                      boolean useSsl, boolean checkServerCertificate, boolean allowPublicKeyRetrieval,
                      Columns columns) {
        this.backend = backend;
        this.host = host;
        this.port = port;
        this.user = user;
        this.password = password;
        this.database = database;
        this.table = table;
        this.poolSize = poolSize;
        this.maxLifetimeSeconds = maxLifetimeSeconds;
        this.useSsl = useSsl;
        this.checkServerCertificate = checkServerCertificate;
        this.allowPublicKeyRetrieval = allowPublicKeyRetrieval;
        this.columns = columns;
    }
}