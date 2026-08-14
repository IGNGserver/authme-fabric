package io.github.authme.fabric;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.MariaDBDataSource;
import io.github.authme.fabric.datasource.MySQLDataSource;
import io.github.authme.fabric.datasource.PostgreSqlDataSource;

/**
 * Verifies that the three network JDBC backends fail closed when no server is
 * listening. It deliberately does not install or start an external database.
 */
public final class ExternalDbSelfTest {

    private ExternalDbSelfTest() { }

    public static void main(String[] args) throws Exception {
        expectFailure("MySQL", () -> new MySQLDataSource(settings()));
        expectFailure("MariaDB", () -> new MariaDBDataSource(settings()));
        expectFailure("PostgreSQL", () -> new PostgreSqlDataSource(settings()));
        System.out.println("AuthMe external-database failure self-test passed.");
    }

    private static DbSettings settings() {
        return new DbSettings(null, "127.0.0.1", "1", "authme", "", "authme", "authme",
            2, 30, false, false, false, Columns.builder().build());
    }

    private static void expectFailure(String name, ThrowingAction action) throws Exception {
        try {
            action.run();
            throw new AssertionError(name + " unexpectedly connected to the reserved test endpoint");
        } catch (java.sql.SQLException expected) {
            // A failed constructor is the required fail-closed result.
        }
    }

    @FunctionalInterface
    private interface ThrowingAction { void run() throws Exception; }
}
