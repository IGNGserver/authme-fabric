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
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;
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
            requirePrivate(database, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
            DataSource.MySqlDefinitionResult unsupported = source.mysqlDefinition(
                DataSource.MySqlDefinitionOperation.DETAILS, null);
            require(!unsupported.supported() && !unsupported.successful()
                && unsupported.error().contains("MySQL/MariaDB"),
                "SQLite must fail closed for the MySQL-only mysqldef utility");

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
            io.github.authme.fabric.security.HashedPassword expectedPassword =
                new io.github.authme.fabric.security.HashedPassword("new-hash", "new-salt");
            io.github.authme.fabric.security.HashedPassword migratedPassword =
                new io.github.authme.fabric.security.HashedPassword("migrated-hash", "migrated-salt");
            require(source.updatePasswordIfMatches("playerone", expectedPassword, migratedPassword),
                "compare-and-set password update failed for the current row");
            require(!source.updatePasswordIfMatches("playerone", expectedPassword,
                    new io.github.authme.fabric.security.HashedPassword("stale-hash", "stale-salt")),
                "stale compare-and-set password update was accepted");
            long firstLogin = System.currentTimeMillis();
            require(source.setLoginState("playerone", "127.0.0.1", firstLogin, true),
                "atomic login-state update failed");
            require(source.updatePasswordAndClearLogin("playerone",
                    new io.github.authme.fabric.security.HashedPassword("recovery-hash", "recovery-salt")),
                "atomic password-recovery state update failed");
            PlayerAuth recovered = source.lookupAuth("playerone").auth();
            require(recovered != null && "recovery-hash".equals(recovered.getHash())
                    && !recovered.isLogged() && !recovered.hasSession(),
                "password recovery did not invalidate the previous login state atomically");
            long replacementLogin = firstLogin + 1L;
            require(source.setLoginState("playerone", "127.0.0.1", replacementLogin, true),
                "replacement login-state update failed");
            require(source.persistDisconnectIfLastLogin("playerone", firstLogin, System.currentTimeMillis(),
                1, 2, 3, 4, 5, "minecraft:overworld", true, false),
                "stale disconnect callback was not treated as a safe no-op");
            require(source.lookupAuth("playerone").auth().isLogged(),
                "stale disconnect callback cleared the replacement login");
            require(source.clearLoginIfLastLogin("playerone", firstLogin),
                "stale login cleanup was not treated as a safe no-op");
            require(source.lookupAuth("playerone").auth().isLogged(),
                "stale login cleanup cleared the replacement login");
            require(source.persistDisconnectIfLastLogin("playerone", replacementLogin,
                System.currentTimeMillis(), 1, 2, 3, 4, 5,
                "minecraft:overworld", true, false), "current disconnect-state update failed");
            PlayerAuth quotaPeer = PlayerAuth.builder()
                .name("quota_peer").realName("QuotaPeer").password("hash", "salt")
                .registrationDate(System.currentTimeMillis()).registrationIp("127.0.0.2")
                .locWorld("minecraft:overworld").build();
            require(source.saveAuth(quotaPeer), "coordinated-login fixture setup failed");
            DataSource.LoginStateResult firstLease = source.acquireLoginState(
                "playerone", "198.51.100.4", 100L, true, 1);
            require(firstLease.acquired(), "first coordinated login lease was not acquired");
            DataSource.LoginStateResult replacementLease = source.acquireLoginState(
                "playerone", "198.51.100.4", 100L, true, 1);
            require(replacementLease.acquired() && replacementLease.version() > firstLease.version(),
                "login fencing version was not monotonic");
            require(!source.renewLoginLease("playerone", firstLease.version(),
                    System.currentTimeMillis()).active(),
                "superseded login lease was renewed");
            DataSource.LoginLeaseResult renewed = source.renewLoginLease(
                "playerone", replacementLease.version(), System.currentTimeMillis());
            require(renewed.successful() && renewed.active(),
                "current login lease was not renewed");
            require(source.queryPurgeCandidates(Long.MAX_VALUE, 100).value().stream()
                    .noneMatch(candidate -> "playerone".equals(candidate.getName())),
                "an account with a live login lease was exposed as a purge candidate");
            DataSource.LoginStateResult quotaRejected = source.acquireLoginState(
                "quota_peer", "198.51.100.4", 101L, true, 1);
            require(quotaRejected.status() == DataSource.LoginStateStatus.LIMIT_REACHED,
                "per-IP login quota was not enforced inside the coordinated transition");
            require(source.updateLastLogin("quota_peer", Long.MAX_VALUE),
                "could not prepare exhausted-fence fixture");
            DataSource.LoginStateResult exhaustedFence = source.acquireLoginState(
                "quota_peer", "198.51.100.5", 102L, true, 1);
            require(exhaustedFence.status() == DataSource.LoginStateStatus.ERROR,
                "an exhausted/corrupt login fence wrapped around and was reused");
            require(source.persistDisconnectIfLastLogin("playerone", firstLease.version(),
                System.currentTimeMillis(), 0, 0, 0, 0, 0,
                "minecraft:overworld", false, false),
                "stale fenced disconnect was not a safe no-op");
            PlayerAuth fenced = source.lookupAuth("playerone").auth();
            require(fenced != null && fenced.isLogged()
                    && fenced.getLastLogin() == replacementLease.version(),
                "stale disconnect cleared a newer coordinated login lease");
            long failureNow = System.currentTimeMillis();
            DataSource.FailureStateResult firstFailure = source.recordFailureState(
                "ip|203.0.113.8", failureNow, 60_000L, 2, 120_000L);
            require(firstFailure.successful() && firstFailure.attempts() == 1
                    && firstFailure.bannedUntil() == 0L,
                "first shared failure attempt was not stored");
            SQLiteDataSource peer = new SQLiteDataSource(settings);
            try {
                DataSource.FailureStateResult secondFailure = peer.recordFailureState(
                    "ip|203.0.113.8", failureNow + 1L, 60_000L, 2, 120_000L);
                require(secondFailure.successful() && secondFailure.attempts() == 2
                        && secondFailure.bannedUntil() > failureNow,
                    "second data-source instance did not share the failure/ban bucket");
                DataSource.FailureStateResult observed = source.readFailureState(
                    "ip|203.0.113.8", failureNow + 2L, 60_000L);
                require(observed.successful() && observed.attempts() == 2,
                    "shared failure state was not visible across instances");
                require(peer.clearFailureState("ip|203.0.113.8")
                        && source.readFailureState("ip|203.0.113.8", failureNow + 3L, 60_000L).attempts() == 0,
                    "shared failure state was not cleared across instances");
            } finally {
                peer.close();
            }
            require(source.getRegisteredNames().contains("playerone"), "registered names did not contain account");
            require(source.queryRegisteredNamesByIp("198.51.100.4").successful()
                && source.queryRegisteredNamesByIp("198.51.100.4").value().contains("playerone"),
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
                && source.queryRecentAccounts(5).value().size() >= 2,
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
            PlayerAuth staleSnapshot = source.lookupAuth("stale").auth();
            require(staleSnapshot != null && source.updatePassword("stale",
                    new io.github.authme.fabric.security.HashedPassword("changed-hash", "changed-salt")),
                "conditional purge race fixture setup failed");
            DataSource.OperationResult stalePurge = source.removeAuthIfUnchanged(staleSnapshot, cutoff);
            require(stalePurge.successful() && stalePurge.affected() == 0
                    && source.lookupAuth("stale").auth() != null,
                "purge deleted an account whose security snapshot changed after candidate lookup");
            PlayerAuth refreshedStale = source.lookupAuth("stale").auth();
            require(refreshedStale != null && source.updateEmail("stale", "fresh@example.test"),
                "conditional purge identity fixture setup failed");
            DataSource.OperationResult identityChangedPurge =
                source.removeAuthIfUnchanged(refreshedStale, cutoff);
            require(identityChangedPurge.successful() && identityChangedPurge.affected() == 0
                    && source.lookupAuth("stale").auth() != null,
                "purge deleted an account whose identity snapshot changed after candidate lookup");
            refreshedStale = source.lookupAuth("stale").auth();
            require(refreshedStale != null
                    && source.removeAuthIfUnchanged(refreshedStale, cutoff).affected() == 1,
                "unchanged purge candidate was not deleted conditionally");
            PlayerAuth bulkStale = PlayerAuth.builder()
                .name("bulk_stale").realName("BulkStale").password("hash", "salt")
                .lastLogin(cutoff - 1_000L).registrationDate(cutoff - 2_000L)
                .locWorld("minecraft:overworld")
                .build();
            require(source.saveAuth(bulkStale), "bounded purge fixture setup failed");
            DataSource.OperationResult purged = source.purgeRegisteredBefore(cutoff, 10);
            require(purged.successful() && purged.affected() == 1
                && source.lookupAuth("bulk_stale").auth() == null
                && source.lookupAuth("activeold").auth() != null,
                "purge did not use the most recent account activity");
            require(source.clearLoggedFlags().successful(), "clearLoggedFlags failed");

            SQLiteDataSource readOnly = new SQLiteDataSource(settings, true);
            try {
                require(readOnly.lookupAuth("playerone").successful(), "read-only SQLite lookup failed");
                readOnly.reload();
                require(readOnly.lookupAuth("playerone").successful(), "read-only SQLite reload changed access mode");
            } finally {
                readOnly.close();
            }

            Path backupDirectory = directory.resolve("backups");
            Path backup = backupDirectory.resolve("backup.sql");
            require(source.backup(backup), "backup failed");
            requirePrivate(backupDirectory, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE));
            requirePrivate(backup, Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE));
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
            require("Cached".equals(cached.getAuth("cached").getRealName()), "cache first lookup failed");
            require(source.updateRealName("cached", "Changed"), "cache external update failed");
            require("Cached".equals(cached.getAuth("cached").getRealName()), "cache did not retain a bounded hit");
            require("Changed".equals(cached.lookupAuth("cached").auth().getRealName()),
                "security-sensitive lookup did not bypass the stale cache");
            require(cached.updateRealName("cached", "ChangedAgain"), "cache write failed");
            require("ChangedAgain".equals(cached.getAuth("cached").getRealName()), "cache write did not invalidate");
            cached.close();
        } finally {
            source.close();
        }
        System.out.println("AuthMe data-source self-test passed.");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void requirePrivate(Path file, Set<PosixFilePermission> expected) throws Exception {
        if (Files.getFileAttributeView(file, java.nio.file.attribute.PosixFileAttributeView.class) == null) return;
        require(Files.getPosixFilePermissions(file).equals(expected),
            "sensitive data file was not restricted to the owner: " + file);
    }
}
