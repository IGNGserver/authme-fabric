package io.github.authme.fabric.datasource;

import java.sql.SQLException;

/** Opens an existing AuthMe schema without running migrations or other DDL. */
public final class ReadOnlyDataSources {

    private ReadOnlyDataSources() { }

    /**
     * Remote callers must provide a database principal with SELECT-only grants. SQLite is also
     * opened with JDBC {@code mode=ro}, giving it an enforceable local read-only boundary.
     */
    public static DataSource open(DbSettings settings) throws SQLException {
        if (settings == null || settings.backend == null) {
            throw new SQLException("Read-only database backend is missing");
        }
        return switch (settings.backend) {
            case MYSQL -> new MySQLDataSource(settings, true);
            case MARIADB -> new MariaDBDataSource(settings, true);
            case POSTGRESQL -> new PostgreSqlDataSource(settings, true);
            case SQLITE -> new SQLiteDataSource(settings, true);
        };
    }
}
