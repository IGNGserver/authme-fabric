package io.github.authme.fabric.network;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.ProxyProtocol;
import net.fabricmc.fabric.api.networking.v1.PayloadTypeRegistry;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

import java.util.concurrent.CompletableFuture;

/** Secure AuthMeBungee/AuthMeVelocity bridge for the 1.21.11 networking API. */
public final class ProxyBridge {

    private ProxyBridge() { }

    public static void register() {
        PayloadTypeRegistry.playC2S().register(AuthMeProxyPayload.TYPE, AuthMeProxyPayload.CODEC);
        PayloadTypeRegistry.playS2C().register(AuthMeProxyPayload.TYPE, AuthMeProxyPayload.CODEC);
        PayloadTypeRegistry.playS2C().register(BungeeConnectPayload.TYPE, BungeeConnectPayload.CODEC);
        ServerPlayNetworking.registerGlobalReceiver(AuthMeProxyPayload.TYPE, (payload, context) ->
            handle(context.server(), context.player(), payload.data()));
    }

    public static void bind(AuthMe auth, MinecraftServer server) {
        auth.setProxyMessageSink((type, name) -> send(server, type, name));
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
            CompletableFuture.supplyAsync(() -> auth.dataSource().queryPremiumUsernames())
                .thenAccept(result -> server.execute(() -> {
                    if (!result.successful()) return;
                    auth.emitProxyPremiumList(result.value());
                }));
            return;
        }
        if (ProxyProtocol.PERFORM_LOGIN.equals(message.type()) && auth.authManager() != null) {
            auth.authManager().forceLoginFromProxy(player, message.premiumUuid());
        }
    }

    private static void send(MinecraftServer server, String type, String playerName) {
        if (server == null || playerName == null) return;
        ServerPlayer carrier = server.getPlayerList().getPlayers().stream()
            .filter(p -> p.getGameProfile().name().equalsIgnoreCase(playerName))
            .findFirst().orElseGet(() -> server.getPlayerList().getPlayers().stream().findFirst().orElse(null));
        if (carrier == null || !ServerPlayNetworking.canSend(carrier, AuthMeProxyPayload.TYPE)) return;
        try {
            ServerPlayNetworking.send(carrier, new AuthMeProxyPayload(ProxyProtocol.encode(type, playerName)));
        } catch (RuntimeException e) {
            Log.error("Could not send AuthMe proxy message", e);
        }
    }

    private static void sendTo(MinecraftServer server, ServerPlayer carrier, String type, String playerName) {
        if (carrier == null || !ServerPlayNetworking.canSend(carrier, AuthMeProxyPayload.TYPE)) return;
        try { ServerPlayNetworking.send(carrier, new AuthMeProxyPayload(ProxyProtocol.encode(type, playerName))); }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy state update", e); }
    }
}
