package io.github.authme.fabric;

import io.github.authme.fabric.antibot.AntiBotManager;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.security.HashAlgorithm;
import io.github.authme.fabric.security.HashedPassword;
import io.github.authme.fabric.security.PasswordSecurity;
import io.github.authme.fabric.totp.TotpProvider;
import io.github.authme.fabric.util.ProxyProtocol;
import io.github.authme.fabric.util.PurgeFileCleaner;
import io.github.authme.fabric.auth.SessionSecurityPolicy;
import io.github.authme.fabric.auth.CommandTokenPolicy;
import io.github.authme.fabric.auth.LoginFailurePolicy;
import io.github.authme.fabric.auth.EmailAddressPolicy;
import io.github.authme.fabric.auth.QuickCommandPolicy;
import io.github.authme.fabric.datasource.PlayerAuth;

import java.util.List;
import java.util.UUID;
import java.nio.file.Files;
import java.nio.file.Path;

/** Lightweight dependency-free regression test executed by the Gradle check task. */
public final class CoreSelfTest {

    private CoreSelfTest() {
    }

    public static void main(String[] args) {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            if (algorithm == HashAlgorithm.CUSTOM || algorithm == HashAlgorithm.TWO_FACTOR) continue;
            PasswordSecurity security = new PasswordSecurity(algorithm, 20, 4, 8, List.of());
            HashedPassword hash = security.computeHash("CorrectHorse9", "PlayerOne");
            require(security.matches("CorrectHorse9", hash, "PlayerOne"), algorithm + " did not round-trip");
            require(!security.matches("wrong-password", hash, "PlayerOne"), algorithm + " accepted a wrong password");
        }
        knownLegacyVectors();

        PasswordSecurity totp = new PasswordSecurity(HashAlgorithm.TWO_FACTOR, 20, 4, 8, List.of());
        HashedPassword secret = totp.computeHash("ignored", "PlayerOne");
        require(TotpProvider.isPlausibleSecret(secret.getHash()), "TWO_FACTOR did not produce a valid secret");

        PasswordSecurity sha = new PasswordSecurity(HashAlgorithm.SHA256, 20, 4, 8, List.of());
        require(sha.verify("x", new HashedPassword("$SHA$not-a-valid-hash"), "PlayerOne") == null,
            "malformed SHA256 hash was not rejected");
        require(sha.verify("x", new HashedPassword("x".repeat(4097)), "PlayerOne") == null,
            "oversized stored password hash was accepted");
        require(sha.verify("x", new HashedPassword("$argon2id$broken"), "PlayerOne") == null,
            "malformed Argon2 hash was not rejected");
        PasswordSecurity argon = new PasswordSecurity(HashAlgorithm.ARGON2ID, 20, 4, 8, List.of());
        String validArgon = argon.computeHash("CorrectHorse9", "PlayerOne").getHash();
        require(argon.matches("CorrectHorse9", new HashedPassword(validArgon), "PlayerOne"),
            "valid Argon2id hash did not round-trip");
        require(argon.verify("x", new HashedPassword(validArgon.replace("m=65536", "m=999999999")),
            "PlayerOne") == null, "unsafe Argon2 memory parameter was not rejected");
        require(!TotpProvider.isPlausibleSecret("A".repeat(257)), "oversized TOTP secret was accepted");
        try {
            TotpProvider.base32Decode("A".repeat(257));
            throw new AssertionError("oversized TOTP secret was decoded");
        } catch (IllegalArgumentException expected) {
            // Corrupt database data must not cause an unbounded allocation.
        }
        sessionSecurityPolicy();
        loginFailurePolicy();
        commandTokenPolicy();
        quickCommandPolicy();
        emailAddressPolicy();
        purgePathSafety();
        proxyProtocolRoundTrip();
        antiBotState();
        System.out.println("AuthMe core self-test passed for all implemented hash algorithms.");
    }

    private static void sessionSecurityPolicy() {
        long login = 1_000_000L;
        require(SessionSecurityPolicy.canResume("192.0.2.10", "192.0.2.10", login,
                login + 59_000L, 60_000L), "same-IP session was rejected");
        require(!SessionSecurityPolicy.canResume("192.0.2.10", "192.0.2.11", login,
                login + 1_000L, 60_000L), "different-IP session was accepted");
        require(!SessionSecurityPolicy.canResume("192.0.2.10", "192.0.2.10", login,
                login + 60_001L, 60_000L), "expired session was accepted");
        require(!SessionSecurityPolicy.canResume(null, "192.0.2.10", login,
                login + 1_000L, 60_000L), "session with missing stored IP was accepted");
        require(SessionSecurityPolicy.canResume("[2001:db8::1]", "2001:DB8::1", login,
                login + 1_000L, 60_000L), "equivalent IPv6 addresses were rejected");
    }

    private static void proxyProtocolRoundTrip() {
        String secret = "self-test-secret-9f4e";
        long now = System.currentTimeMillis();
        UUID premium = UUID.randomUUID();
        byte[] signed = ProxyProtocol.encodePerformLogin(secret, "ProxyTest", now, premium);
        ProxyProtocol.Incoming accepted = ProxyProtocol.parse(signed, secret);
        require(accepted != null && accepted.verified()
                && accepted.playerName().equals("proxytest") && premium.equals(accepted.premiumUuid()),
            "signed proxy login was not accepted");
        require(ProxyProtocol.parse(signed, secret) == null, "proxy replay was not rejected");
        byte[] ordinary = ProxyProtocol.encode(ProxyProtocol.LOGOUT, "ProxyTest");
        require(ProxyProtocol.parse(ordinary, secret).premiumUuid() == null,
            "ordinary proxy message was not parsed");
        byte[] trailing = java.util.Arrays.copyOf(ordinary, ordinary.length + 1);
        require(ProxyProtocol.parse(trailing, secret) == null,
            "proxy message with trailing bytes was accepted");
        require(ProxyProtocol.parse(ProxyProtocol.encodePerformLogin("wrong", "ProxyTest", now, null), secret) == null,
            "proxy message with a wrong secret was accepted");
        require(ProxyProtocol.parse(ProxyProtocol.encodePerformLogin(secret, "ProxyTest",
            Long.MIN_VALUE, null), secret) == null, "overflowing proxy timestamp was accepted");
        ProxyProtocol.Incoming chunk = ProxyProtocol.parse(
            ProxyProtocol.encode(ProxyProtocol.PREMIUM_LIST_CHUNK, "0:1:playerone,playertwo"), secret);
        require(chunk != null && chunk.playerName().equals("0:1:playerone,playertwo"),
            "premium list chunk was not accepted");
        try {
            ProxyProtocol.encode(ProxyProtocol.PREMIUM_LIST_CHUNK, "0:1:bad/name");
            throw new AssertionError("unsafe premium list name was accepted");
        } catch (IllegalArgumentException expected) {
            // Encode-side validation prevents malformed premium state from leaving the server.
        }
    }

    private static void loginFailurePolicy() {
        require(LoginFailurePolicy.decide(true, 3, 3, true, 2, true)
                == LoginFailurePolicy.Action.TEMPBAN,
            "temporary ban did not take precedence over kick/captcha");
        require(LoginFailurePolicy.decide(true, 2, 3, true, 2, true)
                == LoginFailurePolicy.Action.CAPTCHA,
            "captcha was not selected before the temporary-ban threshold");
        require(LoginFailurePolicy.decide(false, 1, 3, false, 2, false)
                == LoginFailurePolicy.Action.NONE,
            "disabled login protections still selected an action");
    }

    private static void commandTokenPolicy() {
        require(CommandTokenPolicy.isAllowed("/login", List.of("/login", "register")),
            "slash-prefixed allow-list command was rejected");
        require(CommandTokenPolicy.isAllowed("  /AUTHME   reload", List.of("authme")),
            "command root was not normalized");
        require(!CommandTokenPolicy.isAllowed("op", List.of("/login", "register")),
            "unlisted command was accepted");
    }

    private static void quickCommandPolicy() {
        require(QuickCommandPolicy.enabled(true, true, true),
            "granted quick-command permission did not enable protection");
        require(QuickCommandPolicy.enabled(true, false, false),
            "missing permission provider disabled the quick-command guard");
        require(!QuickCommandPolicy.enabled(true, false, true),
            "permission-provider denial did not disable the opt-in guard");
        require(QuickCommandPolicy.enabled(false, false, true),
            "disabled permission checks did not preserve the configured guard");
    }

    private static void emailAddressPolicy() {
        require(EmailAddressPolicy.isValid("player+auth@example.test"),
            "valid email address was rejected");
        require(!EmailAddressPolicy.isValid("player..two@example.test"),
            "consecutive-dot local part was accepted");
        require(!EmailAddressPolicy.isValid("player@example..test"),
            "empty domain label was accepted");
        require(!EmailAddressPolicy.isValid("player@-example.test"),
            "domain label with a leading hyphen was accepted");
        require(!EmailAddressPolicy.isValid("player@example.test\r\nBcc: attacker@example.test"),
            "header-injection email was accepted");
        require(!EmailAddressPolicy.isValid("a".repeat(250) + "@example.test"),
            "oversized email address was accepted");
    }

    private static void purgePathSafety() {
        try {
            Path parent = Files.createTempDirectory("authme-purge-selftest-");
            Path root = parent.resolve("server");
            Path outside = parent.resolve("outside");
            UUID uuid = UUID.randomUUID();
            Path outsideFile = outside.resolve(uuid + ".dat");
            Path playerData = root.resolve("world").resolve("playerdata");
            Files.createDirectories(playerData.getParent());
            Files.createDirectories(outside);
            Files.writeString(outsideFile, "must survive");
            try {
                Files.createSymbolicLink(playerData, outside);
            } catch (UnsupportedOperationException | java.nio.file.FileSystemException unsupported) {
                // Some CI filesystems disable symlink creation; the remaining self-tests still
                // cover the parser and authentication boundary on those platforms.
                return;
            }

            Path configDirectory = root.resolve("config").resolve("authme");
            Files.createDirectories(configDirectory);
            Files.writeString(configDirectory.resolve("config.yml"), """
                Purge:
                  removePlayerDat: true
                  defaultWorld: world
                """);
            AuthMeConfig config = new AuthMeConfig(configDirectory);
            require(config.load(), "purge safety configuration did not load");
            PlayerAuth account = PlayerAuth.builder().name("purge_player").realName("Purge_Player")
                .uuid(uuid).build();
            require(PurgeFileCleaner.clean(root, config, List.of(account), true) == 0,
                "purge followed a parent symlink outside the server root");
            require(Files.exists(outsideFile), "purge deleted a file outside the server root");

            Files.delete(playerData);
            Files.createDirectories(playerData);
            Path finalTarget = parent.resolve("outside-final.dat");
            Files.writeString(finalTarget, "must survive");
            Files.createSymbolicLink(playerData.resolve(uuid + ".dat"), finalTarget);
            require(PurgeFileCleaner.clean(root, config, List.of(account), true) == 0,
                "purge followed a final symlink outside the server root");
            require(Files.exists(finalTarget), "purge deleted a final symlink target");
        } catch (Exception exception) {
            throw new AssertionError("purge path safety test failed", exception);
        }
    }

    private static void antiBotState() {
        try {
            Path directory = Files.createTempDirectory("authme-antibot-selftest-");
            Files.writeString(directory.resolve("config.yml"), """
                AntiBot:
                  enableAntiBot: true
                  antibotInterval: 60
                  antibotThreshold: 2
                  antibotDuration: 1
                  antibotDelay: 0
                """);
            AuthMeConfig config = new AuthMeConfig(directory);
            require(config.load(), "AntiBot test configuration did not load");
            AntiBotManager antiBot = new AntiBotManager(config);
            require(!antiBot.notifyJoin("192.0.2.1"), "AntiBot activated before its threshold");
            require(antiBot.notifyJoin("192.0.2.2"), "AntiBot threshold activation was not reported");
            require(antiBot.shouldBlockNewJoins(), "AntiBot did not block inside its safety window");
            require(!antiBot.notifyJoin("192.0.2.3"), "AntiBot repeated its activation notification");
            antiBot.setEnabled(false);
            require(!antiBot.shouldBlockNewJoins(), "disabled AntiBot still blocked a join");
        } catch (Exception e) {
            throw new AssertionError("AntiBot state test failed", e);
        }
    }

    private static void knownLegacyVectors() {
        String user = "Test_Player00";
        known(HashAlgorithm.CMW, "1619d7adc23f4f633f11014d2f22b7d8", null, "password", user);
        known(HashAlgorithm.CRAZYCRYPT1,
            "d5c76eb36417d4e97ec62609619e40a9e549a2598d0dab5a7194fd997a9305af78de2b93f958e150d19dd1e7f821043379ddf5f9c7f352bf27df91ae4913f3e8",
            null, "password", user);
        known(HashAlgorithm.DOUBLEMD5, "696d29e0940a4957748fe3fc9efd22a3", null, "password", user);
        known(HashAlgorithm.IPB3, "f8ecea1ce42b5babef369ff7692dbe3f", "1715b", "password", user);
        known(HashAlgorithm.IPB4, "$2a$13$leEvXu77OIwPwNvtZIJvaeAx8EItGHuR3nIlq8416g0gXeJaQdrr2", "leEvXu77OIwPwNvtZIJval", "password", user);
        known(HashAlgorithm.JOOMLA, "b18c99813cd96df3a706652f47177490:377c4aaf92c5ed57711306909e6065ca", null, "password", user);
        known(HashAlgorithm.MD5VB, "$MD5vb$bd9832fffa287321$5006d371fcb813f2347987f902a024ad", null, "password", user);
        known(HashAlgorithm.MYBB, "57c7a16d860833db5030738f5a465d2b", "acdc14e6", "password", user);
        known(HashAlgorithm.PBKDF2DJANGO, "pbkdf2_sha256$15000$50a7ff2d7e00$t7Qx2CfzMhGEbyCa3Wk5nJvNjj3N+FdxhpwJDerl4Fs=", null, "password", user);
        known(HashAlgorithm.PHPBB, "$2a$10$1rnuna3GBduBy1NQuOpnWODqBfl8CZHeULuBThNfAvkOYDRRQR1Zi", null, "password", user);
        known(HashAlgorithm.PHPFUSION, "f7a606c4eb3fcfbc382906476e05b06f21234a77d1a4eacc0f93f503deb69e70", "6cd1c97c55cb", "password", user);
        known(HashAlgorithm.ROYALAUTH, "5d21ef9236896bc4ac508e524e2da8a0def555dac1cdfc7259d62900d1d3f553826210c369870673ae2cf1c41abcf4f92670d76af1db044d33559324f5c2a339", null, "password", user);
        known(HashAlgorithm.SMF, "9b361c66977bb059d460a20d3c21fb3394772df5", "abcd", "password", user);
        known(HashAlgorithm.WBB3, "8df818ef7d56075ab2744f74b98ad68a375ccac4", "b7415b355492ea60314f259a35733a3092c03e3f", "password", user);
        known(HashAlgorithm.WBB4, "$2a$08$7DGr.wROqEPe0Z3XJS7n5.k.QWehovLHbpI.UkdfRb4ns268WsR6C", null, "password", user);
        known(HashAlgorithm.WORDPRESS, "$P$B9wyjxuU4yrfjnnHNGSzH9ti9CC0Os1", null, "password", user);
        known(HashAlgorithm.XFBCRYPT, "$2a$10$UtuON/ZG.x8EWG/zQbryB.BHfQVrfxk3H7qykzP.UJQ8YiLjZyfqq", null, "password", user);
        known(HashAlgorithm.PHPBB, "$H$7MaSGQb0xe3Fp/a.Q.Ewpw.UKfCv.t0", null, "password", user);
        known(HashAlgorithm.PHPBB, "5f4dcc3b5aa765d61d8327deb882cf99", null, "password", user);
        known(HashAlgorithm.XFBCRYPT,
            "a:1:{s:4:\"hash\";s:60:\"$2a$10$UtuON/ZG.x8EWG/zQbryB.BHfQVrfxk3H7qykzP.UJQ8YiLjZyfqq\";}",
            null, "password", user);
    }

    private static void known(HashAlgorithm algorithm, String hash, String salt, String password, String user) {
        PasswordSecurity security = new PasswordSecurity(algorithm, 20, 10, 8, List.of());
        HashedPassword stored = new HashedPassword(hash, salt);
        require(security.matches(password, stored, user), algorithm + " did not match AuthMe legacy vector");
        require(!security.matches(password + "-wrong", stored, user), algorithm + " accepted a legacy wrong password");
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
