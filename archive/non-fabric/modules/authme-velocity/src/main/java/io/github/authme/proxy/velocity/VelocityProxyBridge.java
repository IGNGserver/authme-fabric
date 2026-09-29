package io.github.authme.proxy.velocity;

import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.player.configuration.PlayerEnteredConfigurationEvent;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import com.velocitypowered.api.proxy.ServerConnection;
import com.velocitypowered.api.proxy.messages.ChannelIdentifier;
import com.velocitypowered.api.proxy.messages.LegacyChannelIdentifier;
import com.velocitypowered.api.proxy.messages.MinecraftChannelIdentifier;
import com.velocitypowered.api.proxy.server.RegisteredServer;
import com.velocitypowered.api.util.UuidUtils;
import io.github.authme.proxy.core.ProxyAuthenticationStore;
import io.github.authme.proxy.core.ProxyConfig;
import io.github.authme.proxy.core.ProxyMessageCodec;
import io.github.authme.proxy.core.PremiumDirectory;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Native Velocity bridge for AuthMe backend servers. */
final class VelocityProxyBridge {

    static final MinecraftChannelIdentifier AUTHME_CHANNEL =
        MinecraftChannelIdentifier.create("authme", "main");
    static final ChannelIdentifier AUTHME_LEGACY_CHANNEL = new LegacyChannelIdentifier("authme:main");
    private static final String IDENTITY = "velocity";
    private static final int MAX_RETRIES = 3;
    private static final int MAX_PREMIUM_NAMES = 16_384;

    private final ProxyServer proxy;
    private final Logger logger;
    private final ProxyAuthenticationStore store = new ProxyAuthenticationStore();
    private final ScheduledExecutorService retries = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "authme-velocity-autologin");
        thread.setDaemon(true);
        return thread;
    });
    private final Set<String> premiumNames = ConcurrentHashMap.newKeySet();
    private final Object premiumSnapshotLock = new Object();
    private final Map<String, PremiumChunkState> premiumChunkBuffers = new HashMap<>();
    private volatile ProxyConfig config;
    private volatile PremiumDirectory premiumDirectory;

    VelocityProxyBridge(ProxyServer proxy, Logger logger, ProxyConfig config) {
        this.proxy = proxy;
        this.logger = logger;
        this.config = config;
        this.premiumDirectory = PremiumDirectory.open(config);
    }

    void reload(ProxyConfig next) {
        PremiumDirectory nextDirectory = PremiumDirectory.open(next);
        PremiumDirectory previous = this.premiumDirectory;
        this.config = next;
        this.premiumDirectory = nextDirectory;
        previous.close();
        logger.info("AuthMe Velocity proxy configuration reloaded");
        sendProxyStartedHandshake();
    }

    void registerChannels() {
        proxy.getChannelRegistrar().register(AUTHME_CHANNEL, AUTHME_LEGACY_CHANNEL);
        sendProxyStartedHandshake();
        logger.info("AuthMe Velocity proxy bridge is ready");
    }

    void onPluginMessage(PluginMessageEvent event) {
        if (!event.getIdentifier().equals(AUTHME_CHANNEL)
            && !event.getIdentifier().equals(AUTHME_LEGACY_CHANNEL)) return;
        if (!(event.getSource() instanceof ServerConnection connection)) {
            event.setResult(PluginMessageEvent.ForwardResult.handled());
            logger.warn("Blocked AuthMe plugin message from a non-server source");
            return;
        }
        event.setResult(PluginMessageEvent.ForwardResult.handled());
        String sourceName = connection.getServer().getServerInfo().getName();
        ProxyConfig.BackendCredential credential = config.backendCredential(sourceName);
        if (credential == null) {
            logger.warn("Rejected AuthMe message from unconfigured backend {}", sourceName);
            return;
        }
        Optional<ProxyMessageCodec.Message> parsed = ProxyMessageCodec.parseBackend(
            event.getData(), credential.secret());
        if (parsed.isEmpty()) {
            logger.warn("Rejected malformed or unsupported AuthMe backend message from {}",
                connection.getServer().getServerInfo().getName());
            return;
        }
        if (!config.acceptsBackendIdentity(sourceName, parsed.get().backendId())) {
            logger.warn("Rejected AuthMe backend identity {} from physical source {}",
                parsed.get().backendId(), sourceName);
            return;
        }
        handleBackendMessage(parsed.get(), connection.getServer());
    }

    private void handleBackendMessage(ProxyMessageCodec.Message message, RegisteredServer source) {
        String name = message.playerName();
        boolean authServer = config.isAuthServer(source.getServerInfo().getName());
        switch (message.type()) {
            case ProxyMessageCodec.LOGIN -> {
                if (!authServer) {
                    logger.warn("Ignored login state from non-auth server {}", source.getServerInfo().getName());
                    return;
                }
                store.markAuthenticated(name);
                cancelAutoLogin(name);
                redirect(name, config.loginServer());
            }
            case ProxyMessageCodec.LOGOUT -> {
                if (!authServer) {
                    logger.warn("Ignored logout state from non-auth server {}", source.getServerInfo().getName());
                    return;
                }
                store.markLoggedOut(name);
                cancelAutoLogin(name);
                redirect(name, config.sendOnLogout() ? config.unloggedUserServer() : "");
            }
            case ProxyMessageCodec.PERFORM_LOGIN_ACK -> {
                if (!authServer) {
                    logger.warn("Ignored auto-login acknowledgement from non-auth server {}",
                        source.getServerInfo().getName());
                    return;
                }
                cancelAutoLogin(name);
            }
            case ProxyMessageCodec.PREMIUM_SET -> {
                if (!authServer) {
                    logger.warn("Ignored premium state from non-auth server {}", source.getServerInfo().getName());
                    return;
                }
                rememberPremium(name, true);
                store.setPremium(name, true);
            }
            case ProxyMessageCodec.PREMIUM_PENDING_SET -> {
                if (!authServer) {
                    logger.warn("Ignored premium state from non-auth server {}", source.getServerInfo().getName());
                    return;
                }
                rememberPremium(name, false);
                store.setPremium(name, false);
            }
            case ProxyMessageCodec.PREMIUM_UNSET -> {
                if (!authServer) {
                    logger.warn("Ignored premium state from non-auth server {}", source.getServerInfo().getName());
                    return;
                }
                rememberPremium(name, false);
                store.setPremium(name, false);
            }
            case ProxyMessageCodec.PREMIUM_LIST -> {
                if (authServer) replacePremiumNames(name);
                else logger.warn("Ignored premium snapshot from non-auth server {}", source.getServerInfo().getName());
            }
            case ProxyMessageCodec.PREMIUM_LIST_CHUNK -> {
                if (authServer) handlePremiumChunk(source.getServerInfo().getName(), name);
                else logger.warn("Ignored premium snapshot chunk from non-auth server {}", source.getServerInfo().getName());
            }
            case ProxyMessageCodec.PROXY_STARTED, ProxyMessageCodec.PERFORM_LOGIN -> {
                // proxy.started is sent by this bridge, and perform.login is proxy-to-backend.
                // Neither direction is accepted as an actionable backend notification.
            }
            default -> logger.debug("Ignoring AuthMe proxy message {}", message.type());
        }
    }

    void onPlayerEnteredConfiguration(PlayerEnteredConfigurationEvent event) {
        if (!config.autoLogin()) return;
        ServerConnection server = event.server();
        if (server == null || !config.isAuthServer(server.getServer().getServerInfo().getName())) return;
        sendAutoLogin(event.player(), server);
    }

    EventTask onPreLogin(PreLoginEvent event) {
        return EventTask.async(() -> {
            PremiumDirectory.Decision decision;
            try {
                decision = premiumDirectory.check(event.getUsername());
            } catch (RuntimeException exception) {
                decision = PremiumDirectory.Decision.UNAVAILABLE;
                logger.error("Authoritative Premium lookup failed", exception);
            }
            if (decision == PremiumDirectory.Decision.UNAVAILABLE) {
                event.setResult(PreLoginEvent.PreLoginComponentResult.denied(
                    Component.text(config.premiumLookupFailureMessage(), NamedTextColor.RED)));
                logger.warn("Denied pre-login because the authoritative Premium directory is unavailable");
            } else if (decision == PremiumDirectory.Decision.PREMIUM) {
                store.setPremium(event.getUsername(), true);
                event.setResult(PreLoginEvent.PreLoginComponentResult.forceOnlineMode());
            } else {
                store.setPremium(event.getUsername(), false);
            }
        });
    }

    void onGameProfileRequest(GameProfileRequestEvent event) {
        String normalized = event.getUsername().toLowerCase(Locale.ROOT);
        if (!store.isPremium(normalized) || !event.isOnlineMode()) return;
        UUID verifiedUuid = event.getOriginalProfile().getId();
        if (verifiedUuid == null) return;
        store.markPremiumVerified(normalized, verifiedUuid);
        if (config.keepOfflineUuidCompatibility()) {
            event.setGameProfile(event.getGameProfile().withId(
                UuidUtils.generateOfflinePlayerUuid(event.getUsername())));
        }
        logger.debug("Stored verified Premium UUID for {}", normalized);
    }

    void onServerConnected(ServerConnectedEvent event) {
        RegisteredServer target = event.getServer();
        ServerConnection current = event.getPlayer().getCurrentServer().orElse(null);
        boolean connectingToAuth = config.isAuthServer(target.getServerInfo().getName());
        boolean leavingAuth = event.getPreviousServer().map(previous -> config.isAuthServer(previous.getServerInfo().getName())).orElse(false);
        String name = event.getPlayer().getUsername();
        // The current premium snapshot carries names only.  Do not use a name-only
        // snapshot as an offline-proxy login credential; only a session that has
        // already authenticated on an AuthMe server may be replayed across servers.
        boolean knownIdentity = store.isAuthenticated(name) || store.isPremiumVerified(name);
        if (!config.autoLogin() || (!connectingToAuth && !leavingAuth && !knownIdentity)) return;
        if (current == null) return;
        sendAutoLogin(event.getPlayer(), current);
    }

    void onServerPreConnect(ServerPreConnectEvent event) {
        if (!config.serverSwitchRequiresAuth()) return;
        Player player = event.getPlayer();
        if (store.isAuthenticated(player.getUsername())) return;
        RegisteredServer target = event.getResult().getServer().orElse(null);
        if (target == null || config.isAuthServer(target.getServerInfo().getName())) return;
        event.setResult(ServerPreConnectEvent.ServerResult.denied());
        player.sendMessage(Component.text(config.serverSwitchKickMessage(), NamedTextColor.RED));
    }

    void onCommandExecute(CommandExecuteEvent event) {
        if (!config.commandsRequireAuth() || !(event.getCommandSource() instanceof Player player)) return;
        RegisteredServer current = player.getCurrentServer().map(ServerConnection::getServer).orElse(null);
        if (current == null || !config.isAuthServer(current.getServerInfo().getName()) || store.isAuthenticated(player.getUsername())) return;
        if (config.isWhitelistedCommand(event.getCommand())) return;
        event.setResult(CommandExecuteEvent.CommandResult.denied());
    }

    void onPlayerChat(PlayerChatEvent event) {
        if (!config.chatRequiresAuth()) return;
        Player player = event.getPlayer();
        RegisteredServer current = player.getCurrentServer().map(ServerConnection::getServer).orElse(null);
        if (current != null && config.isAuthServer(current.getServerInfo().getName()) && !store.isAuthenticated(player.getUsername())) {
            event.setResult(PlayerChatEvent.ChatResult.denied());
        }
    }

    void onDisconnect(DisconnectEvent event) {
        String name = event.getPlayer().getUsername();
        cancelAutoLogin(name);
        store.clear(name);
    }

    void shutdown() {
        retries.shutdownNow();
        premiumDirectory.close();
        proxy.getChannelRegistrar().unregister(AUTHME_CHANNEL, AUTHME_LEGACY_CHANNEL);
    }

    private void sendAutoLogin(Player player, ServerConnection connection) {
        String name = player.getUsername().toLowerCase(Locale.ROOT);
        if (!store.isAuthenticated(name) && !store.isPremiumVerified(name)) return;
        if (!store.tryBeginAutoLogin(name)) return;
        ProxyConfig.BackendCredential credential = config.backendCredential(
            connection.getServer().getServerInfo().getName());
        if (credential == null) {
            cancelAutoLogin(name);
            logger.warn("Cannot send AuthMe auto-login to an unconfigured backend {}",
                connection.getServer().getServerInfo().getName());
            return;
        }
        try {
            if (connection.sendPluginMessage(AUTHME_CHANNEL,
                ProxyMessageCodec.performLogin(name, store.premiumUuid(name), credential.secret()))) {
                scheduleRetry(name);
            } else {
                cancelAutoLogin(name);
            }
        } catch (RuntimeException exception) {
            cancelAutoLogin(name);
            logger.warn("Could not send AuthMe perform.login to {}", name, exception);
        }
    }

    private void scheduleRetry(String name) {
        retries.schedule(() -> {
            if (!store.isAutoLoginPending(name)) return;
            int attempt = store.nextAutoLoginAttempt(name);
            if (attempt < 0 || attempt >= MAX_RETRIES) {
                cancelAutoLogin(name);
                logger.warn("No AuthMe auto-login acknowledgement for {} after {} attempts", name, MAX_RETRIES);
                return;
            }
            Player player = proxy.getPlayer(name).orElse(null);
            ServerConnection connection = player == null ? null : player.getCurrentServer().orElse(null);
            if (connection == null) {
                cancelAutoLogin(name);
                return;
            }
            ProxyConfig.BackendCredential credential = config.backendCredential(
                connection.getServer().getServerInfo().getName());
            if (credential == null) {
                cancelAutoLogin(name);
                return;
            }
            try {
                connection.sendPluginMessage(AUTHME_CHANNEL,
                    ProxyMessageCodec.performLogin(name, store.premiumUuid(name), credential.secret()));
                scheduleRetry(name);
            } catch (RuntimeException exception) {
                logger.debug("AuthMe auto-login retry failed for {}", name, exception);
                scheduleRetry(name);
            }
        }, 1, TimeUnit.SECONDS);
    }

    private void cancelAutoLogin(String name) {
        store.cancelAutoLogin(name);
        store.clearAutoLoginIfIdle(name);
    }

    private void redirect(String playerName, String serverName) {
        if (serverName == null || serverName.isBlank()) return;
        Player player = proxy.getPlayer(playerName).orElse(null);
        RegisteredServer target = proxy.getServer(serverName).orElse(null);
        if (player == null || target == null) return;
        player.createConnectionRequest(target).fireAndForget();
    }

    private void sendProxyStartedHandshake() {
        for (RegisteredServer server : proxy.getAllServers()) {
            String name = server.getServerInfo().getName();
            ProxyConfig.BackendCredential credential = config.backendCredential(name);
            if (config.isAuthServer(name) && credential != null) {
                server.sendPluginMessage(AUTHME_CHANNEL,
                    ProxyMessageCodec.proxyStarted(IDENTITY, credential.secret()));
            }
        }
    }

    private void rememberPremium(String name, boolean enabled) {
        String normalized = name.toLowerCase(Locale.ROOT);
        if (enabled) {
            if (premiumNames.size() < MAX_PREMIUM_NAMES) {
                premiumNames.add(normalized);
                store.setPremium(normalized, true);
            }
        } else {
            premiumNames.remove(normalized);
            store.setPremium(normalized, false);
        }
    }

    private void handlePremiumChunk(String sourceName, String value) {
        Optional<ProxyMessageCodec.PremiumChunk> parsed = ProxyMessageCodec.parsePremiumChunk(value);
        if (parsed.isEmpty()) {
            logger.warn("Rejected malformed premium snapshot chunk from backend");
            return;
        }
        ProxyMessageCodec.PremiumChunk chunk = parsed.get();
        String sourceKey = sourceName.toLowerCase(Locale.ROOT);
        synchronized (premiumSnapshotLock) {
            PremiumChunkState state = premiumChunkBuffers.computeIfAbsent(
                sourceKey, ignored -> new PremiumChunkState());
            if (chunk.sequence() == 0) {
                state.names.clear();
                state.expectedSequence = 0;
            }
            if (state.expectedSequence != chunk.sequence()) {
                int expected = state.expectedSequence;
                premiumChunkBuffers.remove(sourceKey);
                logger.warn("Rejected out-of-order premium snapshot chunk {} (expected {})",
                    chunk.sequence(), expected);
                return;
            }
            if (state.names.size() + chunk.names().size() > MAX_PREMIUM_NAMES) {
                premiumChunkBuffers.remove(sourceKey);
                logger.warn("Rejected oversized premium snapshot");
                return;
            }
            state.names.addAll(chunk.names());
            state.expectedSequence++;
            if (chunk.last()) {
                replacePremiumNames(state.names);
                premiumChunkBuffers.remove(sourceKey);
            }
        }
    }

    private static final class PremiumChunkState {
        private final List<String> names = new ArrayList<>();
        private int expectedSequence;
    }

    private void replacePremiumNames(String csv) {
        Set<String> next = new HashSet<>();
        if (csv != null && !csv.isBlank()) {
            for (String value : csv.split(",", -1)) {
                String normalized = value.trim().toLowerCase(Locale.ROOT);
                if (normalized.matches("[a-z0-9_-]{1,16}") && next.size() < MAX_PREMIUM_NAMES) next.add(normalized);
            }
        }
        Set<String> previous = new HashSet<>(premiumNames);
        premiumNames.clear();
        for (String old : previous) if (!next.contains(old)) store.setPremium(old, false);
        premiumNames.addAll(next);
        for (String current : next) store.setPremium(current, true);
    }

    private void replacePremiumNames(Iterable<String> names) {
        Set<String> next = new HashSet<>();
        for (String value : names) {
            String normalized = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
            if (normalized.matches("[a-z0-9_-]{1,16}") && next.size() < MAX_PREMIUM_NAMES) {
                next.add(normalized);
            }
        }
        Set<String> previous = new HashSet<>(premiumNames);
        premiumNames.clear();
        for (String old : previous) if (!next.contains(old)) store.setPremium(old, false);
        premiumNames.addAll(next);
        for (String current : next) store.setPremium(current, true);
    }
}
