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
        String ssl = settings.useSsl
            ? "&sslMode=" + (settings.checkServerCertificate ? "verify-full" : "trust")
            : "&sslMode=disabled";
        return "jdbc:mariadb://" + settings.host + ":" + settings.port + "/" + settings.database
            + "?user=" + settings.user
            + "&password=" + settings.password
            + "&useUnicode=true&characterEncoding=utf8"
            + ssl
            + (settings.allowPublicKeyRetrieval ? "&allowPublicKeyRetrieval=true" : "")
            + "&autoReconnect=true";
    }
}