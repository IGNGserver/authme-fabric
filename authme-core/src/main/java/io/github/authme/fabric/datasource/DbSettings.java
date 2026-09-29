package io.github.authme.fabric.datasource;

/**
 * Resolved database settings passed to a {@link DataSource} implementation.
 */
public final class DbSettings {

    /**
     * TLS policy shared by all JDBC backends. VERIFY_IDENTITY is the secure default for remote
     * databases; REQUIRED encrypts the connection but deliberately does not verify the server
     * certificate and is retained only for installations with an incomplete PKI setup.
     */
    public enum TlsMode {
        DISABLED,
        REQUIRED,
        VERIFY_CA,
        VERIFY_IDENTITY
    }

    /** Controls whether this process may change the configured account schema. */
    public enum SchemaMode {
        /** Explicit maintenance mode; the database principal must have DDL grants. */
        MIGRATE,
        /** Normal runtime mode; validate the existing schema and never issue DDL. */
        VALIDATE
    }

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
    public final TlsMode tlsMode;
    public final SchemaMode schemaMode;
    public final Columns columns;

    public DbSettings(DataSourceType backend, String host, String port, String user, String password,
                      String database, String table, int poolSize, int maxLifetimeSeconds,
                      boolean useSsl, boolean checkServerCertificate, boolean allowPublicKeyRetrieval,
                      Columns columns) {
        this(backend, host, port, user, password, database, table, poolSize, maxLifetimeSeconds,
            useSsl, checkServerCertificate, allowPublicKeyRetrieval,
            !useSsl ? TlsMode.DISABLED
                : checkServerCertificate ? TlsMode.VERIFY_IDENTITY : TlsMode.REQUIRED,
            defaultSchemaMode(backend), columns);
    }

    public DbSettings(DataSourceType backend, String host, String port, String user, String password,
                      String database, String table, int poolSize, int maxLifetimeSeconds,
                      boolean useSsl, boolean checkServerCertificate, boolean allowPublicKeyRetrieval,
                      TlsMode tlsMode, Columns columns) {
        this(backend, host, port, user, password, database, table, poolSize, maxLifetimeSeconds,
            useSsl, checkServerCertificate, allowPublicKeyRetrieval, tlsMode,
            defaultSchemaMode(backend), columns);
    }

    public DbSettings(DataSourceType backend, String host, String port, String user, String password,
                      String database, String table, int poolSize, int maxLifetimeSeconds,
                      boolean useSsl, boolean checkServerCertificate, boolean allowPublicKeyRetrieval,
                      TlsMode tlsMode, SchemaMode schemaMode, Columns columns) {
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
        this.tlsMode = tlsMode == null
            ? (!useSsl ? TlsMode.DISABLED
                : checkServerCertificate ? TlsMode.VERIFY_IDENTITY : TlsMode.REQUIRED)
            : tlsMode;
        this.schemaMode = schemaMode == null ? defaultSchemaMode(backend) : schemaMode;
        this.columns = columns;
    }

    private static SchemaMode defaultSchemaMode(DataSourceType backend) {
        // A local SQLite file is owned by this installation and must be bootstrappable. Remote
        // schemas default to least-privilege runtime validation and require explicit migration.
        return backend == DataSourceType.SQLITE ? SchemaMode.MIGRATE : SchemaMode.VALIDATE;
    }
}
