package io.github.authme.fabric.datasource;

import java.sql.SQLException;

/**
 * MariaDB data source. MariaDB speaks the MySQL wire protocol and accepts the AuthMe MySQL DDL
 * unchanged, so this only overrides the JDBC driver/URL and the backend type.
 */
public class MariaDBDataSource extends MySQLDataSource {

    public MariaDBDataSource(DbSettings settings) throws SQLException {
        super(settings);
    }

    /** Opens an existing schema without issuing DDL. Use a SELECT-only database principal. */
    public MariaDBDataSource(DbSettings settings, boolean readOnly) throws SQLException {
        super(settings, readOnly);
    }

    @Override
    protected String driverClassName() {
        return "org.mariadb.jdbc.Driver";
    }

    @Override
    public DataSourceType getType() {
        return DataSourceType.MARIADB;
    }

    @Override
    protected String buildJdbcUrl() {
        String ssl = "&sslMode=" + mariaDbSslMode(settings.tlsMode);
        return "jdbc:mariadb://" + settings.host + ":" + settings.port + "/" + settings.database
            // Credentials are passed through the JDBC Properties object in the base class.
            // Keeping them out of the URL prevents '&', '?' and '#' in a password from
            // changing connection properties or leaking into URL-based diagnostics.
            + "?useUnicode=true&characterEncoding=utf8"
            + ssl
            + (settings.allowPublicKeyRetrieval ? "&allowPublicKeyRetrieval=true" : "")
            + "&autoReconnect=true";
    }

    private static String mariaDbSslMode(DbSettings.TlsMode mode) {
        return switch (mode) {
            case DISABLED -> "disable";
            case REQUIRED -> "trust";
            case VERIFY_CA -> "verify-ca";
            case VERIFY_IDENTITY -> "verify-full";
        };
    }
}
