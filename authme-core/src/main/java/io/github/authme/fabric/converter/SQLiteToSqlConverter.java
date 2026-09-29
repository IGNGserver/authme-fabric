package io.github.authme.fabric.converter;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.datasource.SQLiteDataSource;
import io.github.authme.fabric.util.Log;

import java.util.List;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Copies all accounts from an AuthMe-shaped SQLite file into the configured target data source
 * (typically MySQL / MariaDB / PostgreSQL). This is the upstream {@code /authme converter
 * sqliteToSql} migration — useful when a server moves from a single Fabric node (SQLite-backed)
 * to a multi-node setup sharing one remote database, or when migrating from a Spigot AuthMe that
 * was configured with SQLite.
 *
 * <p>The SQLite file is opened read-only; the configured target is the same one AuthMe uses at
 * runtime, so column names and row semantics are identical to AuthMe's.
 */
public final class SQLiteToSqlConverter implements Converter {

    private final String sqlitePath;

    public SQLiteToSqlConverter(String sqlitePath) {
        this.sqlitePath = sqlitePath;
    }

    @Override public String id() { return "sqlitetosql"; }

    @Override public String description() {
        return "Migrate accounts from an AuthMe SQLite file into the currently-configured SQL backend.";
    }

    @Override
    public Result convert(DataSource target) throws Exception {
        if (target.getType() == DataSourceType.SQLITE) {
            return new Result(0, 0, "Refusing: target backend is SQLite. Configure the SQL backend first.");
        }
        if (sqlitePath == null || sqlitePath.isBlank()) {
            return new Result(0, 0, "Refusing: provide a SQLite source path.");
        }
        Path sourceFile;
        try {
            sourceFile = Path.of(sqlitePath).toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException e) {
            return new Result(0, 0, "Refusing: invalid SQLite source path.");
        }
        if (!Files.isRegularFile(sourceFile)) {
            return new Result(0, 0, "Refusing: SQLite source file does not exist.");
        }
        Columns shared = target.getColumns();
        DbSettings sqliteSettings = new DbSettings(
            DataSourceType.SQLITE,
            "", "", "", "",
            sourceFile.toString(),
            "authme",
            2, 1800,
            false, false, false,
            shared);
        SQLiteDataSource source = new SQLiteDataSource(sqliteSettings, true);
        try {
            List<String> names = source.getRegisteredNames();
            int imported = 0, skipped = 0;
            for (String name : names) {
                PlayerAuth a = source.getAuth(name);
                if (a == null) { skipped++; continue; }
                if (target.isAuthAvailable(name)) { skipped++; continue; }
                if (target.saveAuth(a)) imported++; else skipped++;
            }
            Log.info("SQLiteToSql: imported=" + imported + ", skipped=" + skipped);
            return new Result(imported, skipped, null);
        } finally {
            source.close();
        }
    }
}
