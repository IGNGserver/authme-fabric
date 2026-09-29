package io.github.authme.fabric.network;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.ProxyProtocol;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;

/** Secure AuthMeBungee/AuthMeVelocity bridge for the 1.20.5–1.21.10 API. */
public final class ProxyBridge {
    private static final Map<MinecraftServer, UUID> PREMIUM_CARRIERS = new WeakHashMap<>();
    private ProxyBridge() { }

    public static void register() {
        PayloadTypeRegistry.playC2S().register(AuthMeProxyPayload.TYPE, AuthMeProxyPayload.CODEC);
        PayloadTypeRegistry.playS2C().register(AuthMeProxyPayload.TYPE, AuthMeProxyPayload.CODEC);
        PayloadTypeRegistry.playS2C().register(BungeeConnectPayload.TYPE, BungeeConnectPayload.CODEC);
        ServerPlayNetworking.registerGlobalReceiver(AuthMeProxyPayload.TYPE, (payload, context) ->
            handle(context.server(), context.player(), payload.data()));
    }

    public static void bind(AuthMe auth, MinecraftServer server) {
        auth.setProxyMessageSink((type, name) -> send(auth, server, type, name));
    }

    public static void connect(MinecraftServer server, ServerPlayer player, String destination) {
        if (server == null || player == null || destination == null || destination.isBlank()
            || !ServerPlayNetworking.canSend(player, BungeeConnectPayload.TYPE)) return;
        try {
            ServerPlayNetworking.send(player, new BungeeConnectPayload(ProxyProtocol.encodeConnect(destination.trim())));
        } catch (RuntimeException e) {
            Log.error("Could not send proxy Connect message", e);
        }
    }

    private static void handle(MinecraftServer server, ServerPlayer player, byte[] data) {
        AuthMe auth = AuthMe.get();
        if (auth == null || auth.config() == null || !auth.config().bungeecordHook()) return;
        ProxyProtocol.Incoming message = ProxyProtocol.parse(data, auth.config().proxySharedSecret());
        if (message == null) {
            Log.warn("Rejected malformed or unauthenticated AuthMe proxy message from "
                + (player == null ? "unknown" : player.getGameProfile().name()));
            return;
        }
        // proxy.started is received on a client-writable channel.  Never answer an unsigned
        // request with the complete premium-account list, otherwise any player can enumerate it.
        // A future/extended proxy bridge may mark this handshake as verified with the shared key.
        if (ProxyProtocol.PROXY_STARTED.equals(message.type()) && message.verified()
            && ProxyProtocol.isProxyIdentity(message.playerName())
            && player != null && auth.dataSource() != null) {
            synchronized (PREMIUM_CARRIERS) {
                PREMIUM_CARRIERS.put(server, player.getUUID());
            }
            CompletableFuture.supplyAsync(() -> auth.dataSource().queryPremiumUsernames())
                .thenAccept(result -> server.execute(() -> {
                    if (!result.successful()) return;
                    auth.emitProxyPremiumList(result.value());
                }));
            return;
        }
        if (ProxyProtocol.PERFORM_LOGIN.equals(message.type()) && auth.authManager() != null) {
            auth.authManager().forceLoginFromProxy(player, message.playerName(), message.premiumUuid());
        }
    }

    private static void send(AuthMe auth, MinecraftServer server, String type, String playerName) {
        if (auth == null || auth.config() == null || server == null || playerName == null) return;
        ServerPlayer carrier;
        if (ProxyProtocol.PREMIUM_LIST_CHUNK.equals(type)) {
            UUID carrierUuid;
            synchronized (PREMIUM_CARRIERS) { carrierUuid = PREMIUM_CARRIERS.get(server); }
            carrier = carrierUuid == null ? null : server.getPlayerList().getPlayers().stream()
                .filter(p -> carrierUuid.equals(p.getUUID())).findFirst().orElse(null);
        } else {
            carrier = server.getPlayerList().getPlayers().stream()
                .filter(p -> p.getGameProfile().name().equalsIgnoreCase(playerName)).findFirst()
                .orElse(null);
        }
        if (carrier == null || !ServerPlayNetworking.canSend(carrier, AuthMeProxyPayload.TYPE)) return;
        try { ServerPlayNetworking.send(carrier, new AuthMeProxyPayload(ProxyProtocol.encodeSignedBackend(
            auth.config().proxySharedSecret(), auth.config().proxyBackendId(), type, playerName))); }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy message", e); }
    }

    private static void sendTo(AuthMe auth, ServerPlayer carrier, String playerName) {
        if (!ServerPlayNetworking.canSend(carrier, AuthMeProxyPayload.TYPE)) return;
        try { ServerPlayNetworking.send(carrier, new AuthMeProxyPayload(ProxyProtocol.encodeSignedBackend(
            auth.config().proxySharedSecret(), auth.config().proxyBackendId(),
            ProxyProtocol.PREMIUM_SET, playerName))); }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy state update", e); }
    }
}
