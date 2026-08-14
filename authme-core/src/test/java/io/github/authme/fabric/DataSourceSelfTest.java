package io.github.authme.fabric;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.CachingDataSource;
import io.github.authme.fabric.datasource.DataSource;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.datasource.SQLiteDataSource;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

/** Exercises the SQLite schema, pool, CRUD result semantics, e-mail lookup and backup writer. */
public final class DataSourceSelfTest {

    private DataSourceSelfTest() {
    }

    public static void main(String[] args) throws Exception {
        Path directory = Files.createTempDirectory("authme-core-selftest-");
        Path database = directory.resolve("authme.db");
        Columns columns = Columns.builder()
            .salt("salt")
            .playerUuid("uuid")
            .premiumUuid("premiumUUID")
            .build();
        DbSettings settings = new DbSettings(
            DataSourceType.SQLITE, "", "", "", "", database.toString(), "authme",
            3, 1800, false, false, false, columns);

        try {
            new SQLiteDataSource(new DbSettings(
                DataSourceType.SQLITE, "", "", "", "", database.toString(), "authme;DROP",
                2, 1800, false, false, false, columns));
            throw new AssertionError("unsafe SQL identifier was accepted");
        } catch (java.sql.SQLException expected) {
            // Configuration-controlled identifiers are rejected before any JDBC connection opens.
        }

        SQLiteDataSource source = new SQLiteDataSource(settings);
        try {
            require(source.ping(), "SQLite health check failed");
            require(source.countAuths() == 0, "new SQLite database was not empty");

            UUID uuid = UUID.randomUUID();
            PlayerAuth account = PlayerAuth.builder()
                .name("playerone")
                .realName("PlayerOne")
                .password("hash-value", "salt-value")
                .lastIp("127.0.0.1")
                .email("player@example.test")
                .lastLogin(System.currentTimeMillis())
                .registrationDate(System.currentTimeMillis())
                .registrationIp("127.0.0.1")
                .locWorld("minecraft:overworld")
                .uuid(uuid)
                .premiumUuid(uuid)
                .build();
            require(source.saveAuth(account), "saveAuth failed");
            require(source.checkAuthAvailable("playerone").available(), "account availability check failed");
            DataSource.LookupResult lookup = source.lookupAuth("PLAYERONE");
            require(lookup.successful() && lookup.auth() != null, "lookupAuth result was not successful");
            require("PlayerOne".equals(lookup.auth().getRealName()), "real name was not preserved");
            PlayerAuth emptySalt = PlayerAuth.builder().password("hash-with-empty-salt", "").build();
            require("hash-with-empty-salt".equals(emptySalt.toHashedPassword().getHash()),
                "an empty separate salt must not discard the password hash");
            require(source.getAuthByEmail("PLAYER@EXAMPLE.TEST") != null, "case-insensitive e-mail lookup failed");
            require(source.updateEmail("playerone", "new@example.test"), "updateEmail failed");
            require(source.updatePassword("playerone", new io.github.authme.fabric.security.HashedPassword("new-hash", "new-salt")),
                "updatePassword failed");
            require(source.setLoginState("playerone", "127.0.0.1", System.currentTimeMillis(), true),
                "atomic login-state update failed");
            require(source.persistDisconnect("playerone", System.currentTimeMillis(), 1, 2, 3, 4, 5,
                "minecraft:overworld", true, false), "atomic disconnect-state update failed");
            require(source.getRegisteredNames().contains("playerone"), "registered names did not contain account");
            require(source.queryRegisteredNamesByIp("127.0.0.1").successful()
                && source.queryRegisteredNamesByIp("127.0.0.1").value().contains("playerone"),
                "accounts-by-IP query failed");
            require(source.countRegisteredByIp("127.0.0.1").successful()
                && source.countRegisteredByIp("127.0.0.1").count() == 1,
                "registration IP count failed");
            require(source.countRegisteredByEmail("new@example.test").successful()
                && source.countRegisteredByEmail("new@example.test").count() == 1,
                "registration e-mail count failed");
            require(source.queryPremiumUsernames().successful()
                && source.queryPremiumUsernames().value().contains("playerone"),
                "premium username query failed");
            require(source.queryRecentAccounts(5).successful()
                && source.queryRecentAccounts(5).value().size() == 1,
                "recent-account query failed");
            long cutoff = System.currentTimeMillis() - 86_400_000L;
            PlayerAuth stale = PlayerAuth.builder()
                .name("stale").realName("Stale").password("hash", "salt")
                .lastLogin(cutoff - 1_000L).registrationDate(cutoff - 2_000L)
                .locWorld("minecraft:overworld")
                .build();
            PlayerAuth active = PlayerAuth.builder()
                .name("activeold").realName("ActiveOld").password("hash", "salt")
                .lastLogin(System.currentTimeMillis()).registrationDate(cutoff - 2_000L)
                .locWorld("minecraft:overworld")
                .build();
            require(source.saveAuth(stale) && source.saveAuth(active), "purge fixture setup failed");
            DataSource.OperationResult purged = source.purgeRegisteredBefore(cutoff, 10);
            require(purged.successful() && purged.affected() == 1
                && source.lookupAuth("stale").auth() == null
                && source.lookupAuth("activeold").auth() != null,
                "purge did not use the most recent account activity");
            require(source.clearLoggedFlags().successful(), "clearLoggedFlags failed");

            Path backup = directory.resolve("backup.sql");
            require(source.backup(backup), "backup failed");
            String backupText = Files.readString(backup, StandardCharsets.UTF_8);
            require(backupText.contains("INSERT INTO"), "backup did not contain INSERT statements");
            require(backupText.contains("playerone"), "backup did not contain account data");
            source.reload();
            require(source.ping(), "SQLite health check failed after reload");
            require(source.removeAuth("playerone"), "removeAuth failed");
            require(source.lookupAuth("playerone").auth() == null, "removed account was still found");

            // The compatibility cache must cache successful reads, preserve
            // source writes, and invalidate its own entry after a write.
            PlayerAuth cachedAccount = PlayerAuth.builder().name("cached").realName("Cached")
                .password("hash", "salt").registrationDate(System.currentTimeMillis())
                .locWorld("minecraft:overworld").build();
            require(source.saveAuth(cachedAccount), "cache fixture setup failed");
            CachingDataSource cached = new CachingDataSource(source, 60_000, 120_000);
            require("Cached".equals(cached.lookupAuth("cached").auth().getRealName()), "cache first lookup failed");
            require(source.updateRealName("cached", "Changed"), "cache external update failed");
            require("Cached".equals(cached.lookupAuth("cached").auth().getRealName()), "cache did not retain a bounded hit");
            require(cached.updateRealName("cached", "ChangedAgain"), "cache write failed");
            require("ChangedAgain".equals(cached.lookupAuth("cached").auth().getRealName()), "cache write did not invalidate");
            cached.close();
        } finally {
            source.close();
        }
        System.out.println("AuthMe data-source self-test passed.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
