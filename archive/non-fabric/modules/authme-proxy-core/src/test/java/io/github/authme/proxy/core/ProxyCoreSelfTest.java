package io.github.authme.proxy.core;

import io.github.authme.fabric.datasource.Columns;
import io.github.authme.fabric.datasource.DataSourceType;
import io.github.authme.fabric.datasource.DbSettings;
import io.github.authme.fabric.datasource.PlayerAuth;
import io.github.authme.fabric.datasource.SQLiteDataSource;
import io.github.authme.fabric.util.ProxyProtocol;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Dependency-light regression test for proxy boundaries and state transitions. */
public final class ProxyCoreSelfTest {

    private ProxyCoreSelfTest() { }

    public static void main(String[] args) throws Exception {
        String secret = "proxy-self-test-secret-2026";
        UUID premium = UUID.randomUUID();
        byte[] signed = ProxyMessageCodec.performLogin("Player_1", premium, secret);
        ProxyProtocol.Incoming accepted = ProxyProtocol.parse(signed, secret);
        require(accepted != null && accepted.verified() && "player_1".equals(accepted.playerName()),
            "signed perform.login was not accepted");
        require(ProxyProtocol.parse(signed, secret) == null, "proxy replay was accepted");
        byte[] backendLogin = ProxyMessageCodec.signedBackend(
            ProxyProtocol.LOGIN, "Player_1", secret, "lobby");
        require(ProxyMessageCodec.parseBackend(backendLogin, secret).isPresent(),
            "signed backend login notification was not parsed");
        require(ProxyMessageCodec.parseBackend(backendLogin, "wrong-secret").isEmpty(),
            "backend notification with the wrong secret was accepted");
        require(ProxyMessageCodec.parseBackend(ProxyMessageCodec.simple(
            ProxyProtocol.LOGIN, "Player_1"), secret).isEmpty(),
            "unsigned backend login notification was accepted");
        require(ProxyMessageCodec.parseBackend(signed, secret).isEmpty(),
            "backend perform.login was accepted");
        byte[] handshake = ProxyMessageCodec.proxyStarted("velocity", secret);
        ProxyProtocol.Incoming verifiedHandshake = ProxyProtocol.parse(handshake, secret);
        require(verifiedHandshake != null && verifiedHandshake.verified()
                && "velocity".equals(verifiedHandshake.playerName()), "signed proxy handshake was not accepted");
        require(ProxyProtocol.parse(handshake, secret) == null, "proxy handshake replay was accepted");
        ProxyMessageCodec.PremiumChunk premiumChunk = ProxyMessageCodec.parsePremiumChunk(
            "3:1:Premium_One,Player-2").orElseThrow();
        require(premiumChunk.sequence() == 3 && premiumChunk.last()
                && premiumChunk.names().equals(List.of("premium_one", "player-2")),
            "premium snapshot chunk was not normalized");
        require(ProxyMessageCodec.parsePremiumChunk("2:0:bad/name").isEmpty(),
            "malformed premium snapshot chunk was accepted");

        ProxyAuthenticationStore store = new ProxyAuthenticationStore();
        store.markAuthenticated("Player_1");
        require(store.isAuthenticated("player_1"), "authentication state was not stored");
        store.setPremium("Player_1", true);
        store.markPremiumVerified("Player_1", premium);
        require(store.isPremium("player_1") && store.isPremiumVerified("player_1")
                && premium.equals(store.premiumUuid("player_1")),
            "verified premium identity was not stored separately from AuthMe login state");
        store.setPremium("Player_1", false);
        require(!store.isPremiumVerified("player_1") && store.premiumUuid("player_1") == null,
            "premium identity was not cleared when premium state was removed");
        store.setPremium("Player_1", true);
        store.markPremiumVerified("Player_1", premium);
        store.markLoggedOut("Player_1");
        require(!store.isAuthenticated("player_1") && !store.isPremiumVerified("player_1")
                && store.premiumUuid("player_1") == null,
            "logout retained a connection-scoped premium identity");
        store.beginAutoLogin("Player_1");
        require(store.isAutoLoginPending("player_1") && store.nextAutoLoginAttempt("player_1") == 0,
            "auto-login pending state was not started");
        store.cancelAutoLogin("player_1");
        require(!store.isAutoLoginPending("player_1"), "auto-login pending state was not cancelled");
        store.markPremiumVerified("Player_1", premium);
        store.beginAutoLogin("Player_1");
        store.cancelAutoLogin("Player_1");
        store.clearAutoLoginIfIdle("Player_1");
        require(store.isPremiumVerified("player_1") && premium.equals(store.premiumUuid("player_1")),
            "failed auto-login cleanup discarded a verified premium identity");

        String gameSecret = "proxy-self-test-game-secret-2026";
        ProxyConfig config = ProxyConfig.from(Map.ofEntries(
            Map.entry("authServers", java.util.List.of("Lobby", "  game-1 ")),
            Map.entry("backendCredentials.lobby.backendId", "lobby"),
            Map.entry("backendCredentials.lobby.secret", secret),
            Map.entry("backendCredentials.game-1.backendId", "game-1"),
            Map.entry("backendCredentials.game-1.secret", gameSecret),
            Map.entry("commands.requireAuth", true),
            Map.entry("commands.whitelist", java.util.List.of("login", "/REGISTER now")),
            Map.entry("premium.keepOfflineUuidCompatibility", false)), secret);
        require(config.isAuthServer("lobby") && config.isAuthServer("GAME-1"), "server normalization failed");
        require(config.acceptsBackendIdentity("lobby", "LOBBY")
                && !config.acceptsBackendIdentity("lobby", "game-1"),
            "physical backend source was not bound to its authenticated backendId");
        require(secret.equals(config.backendCredential("lobby").secret())
                && gameSecret.equals(config.backendCredential("game-1").secret()),
            "per-backend credentials were not isolated");
        require(config.isWhitelistedCommand("/login password") && config.isWhitelistedCommand("register x"),
            "command normalization failed");
        require(!config.isWhitelistedCommand("/op me"), "unlisted command was accepted");
        try {
            ProxyConfig.from(Map.of(), "too-short");
            throw new AssertionError("weak proxy secret was accepted");
        } catch (IllegalArgumentException expected) {
            // Native proxy startup must fail closed instead of silently using a weak key.
        }

        Path dir = Files.createTempDirectory("authme-proxy-config-selftest-");
        ProxyConfig loaded = ProxyConfig.load(dir);
        require(loaded.sharedSecret().length() >= 32 && Files.exists(dir.resolve("proxySharedSecret.txt")),
            "missing proxy secret was not generated safely");
        Files.writeString(dir.resolve("config.yml"), "x: '" + "a".repeat(300_000) + "'\n");
        try {
            ProxyConfig.load(dir);
            throw new AssertionError("oversized proxy YAML was accepted");
        } catch (RuntimeException | java.io.IOException expected) {
            // Proxy configuration is operator-controlled, but malformed/oversized input must
            // still fail closed instead of consuming unbounded parser memory.
        }
        StringBuilder nestedYaml = new StringBuilder();
        for (int i = 0; i < 24; i++) {
            nestedYaml.append("  ".repeat(i)).append("level").append(i).append(":\n");
        }
        nestedYaml.append("  ".repeat(24)).append("value: 1\n");
        Files.writeString(dir.resolve("config.yml"), nestedYaml);
        try {
            ProxyConfig.load(dir);
            throw new AssertionError("overly nested proxy YAML was accepted");
        } catch (RuntimeException | java.io.IOException expected) {
            // Parser nesting is bounded independently from the file-size bound.
        }
        loopbackBackendFlow(secret);
        authoritativePremiumDirectory();
        System.out.println("AuthMe proxy core self-test passed.");
    }

    private static void authoritativePremiumDirectory() throws Exception {
        Path directory = Files.createTempDirectory("authme-premium-directory-selftest-");
        Path database = directory.resolve("authme.db");
        Columns columns = Columns.builder().premiumUuid("premiumUUID").build();
        DbSettings settings = new DbSettings(DataSourceType.SQLITE, "", "", "", "",
            database.toString(), "authme", 2, 300, false, false, false, columns);
        UUID premiumUuid = UUID.randomUUID();
        SQLiteDataSource writer = new SQLiteDataSource(settings);
        try {
            require(writer.saveAuth(PlayerAuth.builder()
                .name("premium_one").realName("Premium_One").password("hash", null)
                .registrationDate(System.currentTimeMillis()).registrationIp("127.0.0.1")
                .locWorld("world").premiumUuid(premiumUuid).build()),
                "could not seed Premium directory self-test");
        } finally {
            writer.close();
        }

        String secret = "premium-directory-secret-2026";
        ProxyConfig config = ProxyConfig.from(Map.ofEntries(
            Map.entry("authServers", List.of("lobby")),
            Map.entry("backendCredentials.lobby.backendId", "backend"),
            Map.entry("backendCredentials.lobby.secret", secret),
            Map.entry("premium.enabled", true),
            Map.entry("premium.database.backend", "SQLITE"),
            Map.entry("premium.database.database", database.toString()),
            Map.entry("premium.database.table", "authme"),
            Map.entry("premium.database.columns.username", "username"),
            Map.entry("premium.database.columns.premiumUuid", "premiumUUID")), secret);
        try (PremiumDirectory premiumDirectory = PremiumDirectory.open(config)) {
            require(premiumDirectory.check("PREMIUM_ONE") == PremiumDirectory.Decision.PREMIUM,
                "cold-start Premium database lookup did not force verified identity");
            require(premiumDirectory.check("offline_user") == PremiumDirectory.Decision.NON_PREMIUM,
                "non-Premium user was incorrectly forced online");
        }
    }

    /**
     * Exercises the two-backend state machine without loading Velocity or Bungee classes.
     * The platform bridges are deliberately thin adapters around this wire contract, so this
     * catches direction, source-server and replay regressions before a real proxy is available.
     */
    private static void loopbackBackendFlow(String secret) {
        ProxyAuthenticationStore store = new ProxyAuthenticationStore();

        backendNotification(store, true, secret,
            ProxyMessageCodec.signedBackend(ProxyProtocol.LOGIN, "Alice", secret, "lobby"));
        require(store.isAuthenticated("alice"), "auth backend login did not reach proxy state");

        require(store.tryBeginAutoLogin("alice"), "first backend switch did not start auto-login");
        byte[] forwarded = ProxyMessageCodec.performLogin("Alice", null, secret);
        ProxyProtocol.Incoming accepted = ProxyProtocol.parse(forwarded, secret);
        require(accepted != null && accepted.verified() && "alice".equals(accepted.playerName()),
            "backend auto-login payload was not accepted");
        require(ProxyProtocol.parse(forwarded, secret) == null,
            "the same auto-login payload was accepted twice");

        // A normal backend cannot change the proxy's authentication state.
        backendNotification(store, false, secret,
            ProxyMessageCodec.signedBackend(ProxyProtocol.LOGOUT, "Alice", secret, "game-1"));
        require(store.isAuthenticated("alice"), "non-auth backend forged a logout");

        backendNotification(store, true, secret,
            ProxyMessageCodec.signedBackend(ProxyProtocol.PERFORM_LOGIN_ACK, "Alice", secret, "lobby"));
        require(!store.isAutoLoginPending("alice"), "auth backend ACK did not cancel retry state");

        // A second auth backend may report logout; future switches must not receive a stale proof.
        backendNotification(store, true, secret,
            ProxyMessageCodec.signedBackend(ProxyProtocol.LOGOUT, "Alice", secret, "lobby"));
        require(!store.isAuthenticated("alice") && store.premiumUuid("alice") == null,
            "auth backend logout retained proxy authentication state");
        require(!store.isAuthenticated("alice") && !store.isPremiumVerified("alice"),
            "auth backend logout retained an auto-login identity proof");
    }

    private static void backendNotification(ProxyAuthenticationStore store, boolean authServer,
                                             String secret, byte[] payload) {
        ProxyMessageCodec.parseBackend(payload, secret).ifPresent(message -> {
            if (!authServer) return;
            if (ProxyProtocol.LOGIN.equals(message.type())) store.markAuthenticated(message.playerName());
            else if (ProxyProtocol.LOGOUT.equals(message.type())) store.markLoggedOut(message.playerName());
            else if (ProxyProtocol.PERFORM_LOGIN_ACK.equals(message.type())) {
                store.cancelAutoLogin(message.playerName());
                store.clearAutoLoginIfIdle(message.playerName());
            }
        });
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
