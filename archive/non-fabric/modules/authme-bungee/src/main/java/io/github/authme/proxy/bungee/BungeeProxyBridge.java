package io.github.authme.proxy.bungee;

import io.github.authme.proxy.core.ProxyAuthenticationStore;
import io.github.authme.proxy.core.ProxyConfig;
import io.github.authme.proxy.core.ProxyMessageCodec;
import io.github.authme.proxy.core.PremiumDirectory;
import net.md_5.bungee.api.ChatColor;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.chat.TextComponent;
import net.md_5.bungee.api.config.ServerInfo;
import net.md_5.bungee.api.event.ChatEvent;
import net.md_5.bungee.api.event.PluginMessageEvent;
import net.md_5.bungee.api.event.PlayerDisconnectEvent;
import net.md_5.bungee.api.event.PostLoginEvent;
import net.md_5.bungee.api.event.PreLoginEvent;
import net.md_5.bungee.api.event.ServerConnectEvent;
import net.md_5.bungee.api.event.ServerSwitchEvent;
import net.md_5.bungee.api.connection.ProxiedPlayer;
import net.md_5.bungee.api.connection.Server;
import net.md_5.bungee.api.plugin.Listener;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.event.EventHandler;
import net.md_5.bungee.event.EventPriority;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

/** Native BungeeCord/Waterfall bridge for AuthMe backend servers. */
final class BungeeProxyBridge implements Listener {

    static final String AUTHME_CHANNEL = "authme:main";
    private static final String IDENTITY = "bungee";
    private static final int MAX_RETRIES = 3;
    private static final int MAX_PREMIUM_NAMES = 16_384;

    private final ProxyServer proxy;
    private final Plugin plugin;
    private final Logger logger;
    private final ProxyAuthenticationStore store = new ProxyAuthenticationStore();
    private final ScheduledExecutorService retries = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread thread = new Thread(r, "authme-bungee-autologin");
        thread.setDaemon(true);
        return thread;
    });
    private final Set<String> premiumNames = ConcurrentHashMap.newKeySet();
    private final Object premiumSnapshotLock = new Object();
    private final Map<String, PremiumChunkState> premiumChunkBuffers = new HashMap<>();
    private volatile ProxyConfig config;
    private volatile PremiumDirectory premiumDirectory;

    BungeeProxyBridge(ProxyServer proxy, Plugin plugin, Logger logger, ProxyConfig config) {
        this.proxy = proxy;
        this.plugin = plugin;
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
        logger.info("AuthMe Bungee proxy configuration reloaded");
        sendProxyStartedHandshake();
    }

    void registerChannels() {
        proxy.registerChannel(AUTHME_CHANNEL);
        sendProxyStartedHandshake();
        logger.info("AuthMe native Bungee proxy bridge is ready");
    }

    @EventHandler
    public void onPluginMessage(PluginMessageEvent event) {
        if (!AUTHME_CHANNEL.equals(event.getTag())) return;
        if (!(event.getSender() instanceof Server server)) {
            event.setCancelled(true);
            logger.warning("Blocked AuthMe plugin message from a non-server source");
            return;
        }
        event.setCancelled(true);
        String sourceName = server.getInfo().getName();
        ProxyConfig.BackendCredential credential = config.backendCredential(sourceName);
        if (credential == null) {
            logger.warning("Rejected AuthMe message from unconfigured backend " + sourceName);
            return;
        }
        Optional<ProxyMessageCodec.Message> parsed = ProxyMessageCodec.parseBackend(
            event.getData(), credential.secret());
        if (parsed.isEmpty()) {
            logger.warning("Rejected malformed AuthMe backend message from " + server.getInfo().getName());
            return;
        }
        if (!config.acceptsBackendIdentity(sourceName, parsed.get().backendId())) {
            logger.warning("Rejected AuthMe backend identity " + parsed.get().backendId()
                + " from physical source " + sourceName);
            return;
        }
        handleBackendMessage(parsed.get(), server.getInfo());
    }

    private void handleBackendMessage(ProxyMessageCodec.Message message, ServerInfo source) {
        String name = message.playerName();
        boolean authServer = config.isAuthServer(source.getName());
        switch (message.type()) {
            case ProxyMessageCodec.LOGIN -> {
                if (!authServer) {
                    logger.warning("Ignored login state from non-auth server " + source.getName());
                    return;
                }
                store.markAuthenticated(name);
                cancelAutoLogin(name);
                redirect(name, config.loginServer());
            }
            case ProxyMessageCodec.LOGOUT -> {
                if (!authServer) {
                    logger.warning("Ignored logout state from non-auth server " + source.getName());
                    return;
                }
                store.markLoggedOut(name);
                cancelAutoLogin(name);
                redirect(name, config.sendOnLogout() ? config.unloggedUserServer() : "");
            }
            case ProxyMessageCodec.PERFORM_LOGIN_ACK -> {
                if (!authServer) {
                    logger.warning("Ignored auto-login acknowledgement from non-auth server " + source.getName());
                    return;
                }
                cancelAutoLogin(name);
            }
            case ProxyMessageCodec.PREMIUM_SET -> {
                if (!authServer) {
                    logger.warning("Ignored premium state from non-auth server " + source.getName());
                    return;
                }
                rememberPremium(name, true);
                store.setPremium(name, true);
            }
            case ProxyMessageCodec.PREMIUM_PENDING_SET, ProxyMessageCodec.PREMIUM_UNSET -> {
                if (!authServer) {
                    logger.warning("Ignored premium state from non-auth server " + source.getName());
                    return;
                }
                rememberPremium(name, false);
                store.setPremium(name, false);
            }
            case ProxyMessageCodec.PREMIUM_LIST -> {
                if (authServer) replacePremiumNames(name);
                else logger.warning("Ignored premium snapshot from non-auth server " + source.getName());
            }
            case ProxyMessageCodec.PREMIUM_LIST_CHUNK -> {
                if (authServer) handlePremiumChunk(source.getName(), name);
                else logger.warning("Ignored premium snapshot chunk from non-auth server " + source.getName());
            }
            case ProxyMessageCodec.PROXY_STARTED, ProxyMessageCodec.PERFORM_LOGIN -> {
                // These are handshake/request directions, not backend notifications.
            }
            default -> logger.fine("Ignoring AuthMe proxy message " + message.type());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onServerConnect(ServerConnectEvent event) {
        if (!config.serverSwitchRequiresAuth() || event.isCancelled()) return;
        ProxiedPlayer player = event.getPlayer();
        if (store.isAuthenticated(player.getName()) || config.isAuthServer(event.getTarget().getName())) return;
        event.setCancelled(true);
        player.sendMessage(new TextComponent(ChatColor.RED + config.serverSwitchKickMessage()));
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPreLogin(PreLoginEvent event) {
        event.registerIntent(plugin);
        proxy.getScheduler().runAsync(plugin, () -> {
            try {
                PremiumDirectory.Decision decision;
                try {
                    decision = premiumDirectory.check(event.getConnection().getName());
                } catch (RuntimeException exception) {
                    decision = PremiumDirectory.Decision.UNAVAILABLE;
                    logger.warning("Authoritative Premium lookup failed: " + exception.getMessage());
                }
                if (decision == PremiumDirectory.Decision.UNAVAILABLE) {
                    event.setCancelled(true);
                    event.setCancelReason(config.premiumLookupFailureMessage());
                    logger.warning("Denied pre-login because the authoritative Premium directory is unavailable");
                } else if (decision == PremiumDirectory.Decision.PREMIUM) {
                    store.setPremium(event.getConnection().getName(), true);
                    event.getConnection().setOnlineMode(true);
                } else {
                    store.setPremium(event.getConnection().getName(), false);
                }
            } finally {
                event.completeIntent(plugin);
            }
        });
    }

    @EventHandler
    public void onPostLogin(PostLoginEvent event) {
        ProxiedPlayer player = event.getPlayer();
        if (store.isPremium(player.getName())
            && player.getPendingConnection().isOnlineMode() && player.getUniqueId() != null) {
            store.markPremiumVerified(player.getName(), player.getUniqueId());
            logger.fine("Stored verified Premium UUID for " + player.getName());
        }
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onChat(ChatEvent event) {
        if (event.isCancelled() || !(event.getSender() instanceof ProxiedPlayer player)) return;
        Server current = player.getServer();
        if (current == null || !config.isAuthServer(current.getInfo().getName()) || store.isAuthenticated(player.getName())) return;
        if (event.isCommand() && config.commandsRequireAuth() && !config.isWhitelistedCommand(event.getMessage())) {
            event.setCancelled(true);
        } else if (!event.isCommand() && config.chatRequiresAuth()) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onServerSwitch(ServerSwitchEvent event) {
        ProxiedPlayer player = event.getPlayer();
        Server current = player.getServer();
        if (current != null && config.isAuthServer(current.getInfo().getName())) sendProxyStartedHandshake(current.getInfo());
        if (!config.autoLogin() || current == null) return;
        boolean enteringAuth = config.isAuthServer(current.getInfo().getName());
        boolean leavingAuth = event.getFrom() != null && config.isAuthServer(event.getFrom().getName());
        // Premium snapshots contain usernames only; they are metadata, never an
        // offline-proxy login credential.  Only an authenticated AuthMe session
        // can be replayed during a server switch.
        boolean knownIdentity = store.isAuthenticated(player.getName())
            || store.isPremiumVerified(player.getName());
        if (enteringAuth || leavingAuth || knownIdentity) sendAutoLogin(player, current);
    }

    @EventHandler
    public void onDisconnect(PlayerDisconnectEvent event) {
        String name = event.getPlayer().getName();
        cancelAutoLogin(name);
        store.clear(name);
    }

    void shutdown() {
        retries.shutdownNow();
        premiumDirectory.close();
        proxy.unregisterChannel(AUTHME_CHANNEL);
    }

    private void sendAutoLogin(ProxiedPlayer player, Server current) {
        String name = player.getName().toLowerCase(Locale.ROOT);
        if (!store.isAuthenticated(name) && !store.isPremiumVerified(name)) return;
        if (!store.tryBeginAutoLogin(name)) return;
        ProxyConfig.BackendCredential credential = config.backendCredential(current.getInfo().getName());
        if (credential == null) {
            cancelAutoLogin(name);
            logger.warning("Cannot send AuthMe auto-login to unconfigured backend " + current.getInfo().getName());
            return;
        }
        try {
            current.getInfo().sendData(AUTHME_CHANNEL,
                ProxyMessageCodec.performLogin(name, store.premiumUuid(name), credential.secret()), false);
            scheduleRetry(name);
        } catch (RuntimeException exception) {
            cancelAutoLogin(name);
            logger.warning("Could not send AuthMe perform.login to " + name + ": " + exception.getMessage());
        }
    }

    private void scheduleRetry(String name) {
        retries.schedule(() -> {
            if (!store.isAutoLoginPending(name)) return;
            int attempt = store.nextAutoLoginAttempt(name);
            if (attempt < 0 || attempt >= MAX_RETRIES) {
                cancelAutoLogin(name);
                logger.warning("No AuthMe auto-login acknowledgement for " + name + " after " + MAX_RETRIES + " attempts");
                return;
            }
            ProxiedPlayer player = proxy.getPlayer(name);
            Server current = player == null ? null : player.getServer();
            if (current == null) {
                cancelAutoLogin(name);
                return;
            }
            ProxyConfig.BackendCredential credential = config.backendCredential(current.getInfo().getName());
            if (credential == null) {
                cancelAutoLogin(name);
                return;
            }
            try {
                current.getInfo().sendData(AUTHME_CHANNEL,
                    ProxyMessageCodec.performLogin(name, store.premiumUuid(name), credential.secret()), false);
                scheduleRetry(name);
            } catch (RuntimeException exception) {
                logger.fine("AuthMe auto-login retry failed for " + name + ": " + exception.getMessage());
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
        ProxiedPlayer player = proxy.getPlayer(playerName);
        ServerInfo target = proxy.getServerInfo(serverName);
        if (player != null && target != null) player.connect(target);
    }

    private void sendProxyStartedHandshake() {
        for (ServerInfo server : proxy.getServers().values()) {
            if (config.isAuthServer(server.getName())) sendProxyStartedHandshake(server);
        }
    }

    private void sendProxyStartedHandshake(ServerInfo server) {
        // The handshake belongs to the backend channel, not to an already connected player.
        // Waiting for a player made an empty authentication backend start without a verified
        // proxy state until the first connection had already entered the server.
        ProxyConfig.BackendCredential credential = config.backendCredential(server.getName());
        if (credential != null) {
            server.sendData(AUTHME_CHANNEL,
                ProxyMessageCodec.proxyStarted(IDENTITY, credential.secret()), false);
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
            logger.warning("Rejected malformed premium snapshot chunk from backend");
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
                logger.warning("Rejected out-of-order premium snapshot chunk " + chunk.sequence());
                return;
            }
            if (state.names.size() + chunk.names().size() > MAX_PREMIUM_NAMES) {
                premiumChunkBuffers.remove(sourceKey);
                logger.warning("Rejected oversized premium snapshot");
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
