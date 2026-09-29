package io.github.authme.fabric.network;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.ProxyProtocol;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;

/** Secure raw-channel AuthMe proxy bridge for Minecraft 1.19.4–1.20.4. */
public final class ProxyBridge {
    private static final int MAX_PAYLOAD_BYTES = 32_767;
    private static final ResourceLocation CHANNEL = new ResourceLocation("authme", "main");
    private static final ResourceLocation BUNGEE_CHANNEL = new ResourceLocation("bungeecord", "main");
    private static final Map<MinecraftServer, UUID> PREMIUM_CARRIERS = new WeakHashMap<>();
    private ProxyBridge() { }

    public static void register() {
        ServerPlayNetworking.registerGlobalReceiver(CHANNEL, (server, player, handler, buf, responseSender) -> {
            if (buf.readableBytes() > MAX_PAYLOAD_BYTES) {
                Log.warn("Rejected oversized AuthMe proxy payload from "
                    + (player == null ? "unknown" : player.getGameProfile().getName()));
                return;
            }
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            server.execute(() -> handle(server, player, data));
        });
    }

    public static void bind(AuthMe auth, MinecraftServer server) {
        auth.setProxyMessageSink((type, name) -> send(auth, server, type, name));
    }

    public static void connect(MinecraftServer server, ServerPlayer player, String destination) {
        if (server == null || player == null || destination == null || destination.isBlank()) return;
        FriendlyByteBuf buf = new FriendlyByteBuf(io.netty.buffer.Unpooled.buffer());
        try {
            buf.writeBytes(ProxyProtocol.encodeConnect(destination.trim()));
            ServerPlayNetworking.send(player, BUNGEE_CHANNEL, buf);
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
                + (player == null ? "unknown" : player.getGameProfile().getName()));
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
                .filter(p -> p.getGameProfile().getName().equalsIgnoreCase(playerName)).findFirst()
                .orElse(null);
        }
        if (carrier == null) return;
        FriendlyByteBuf buf = new FriendlyByteBuf(io.netty.buffer.Unpooled.buffer());
        try {
            buf.writeBytes(ProxyProtocol.encodeSignedBackend(auth.config().proxySharedSecret(),
                auth.config().proxyBackendId(), type, playerName));
            ServerPlayNetworking.send(carrier, CHANNEL, buf);
        }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy message", e); }
    }

    private static void sendTo(AuthMe auth, ServerPlayer carrier, String playerName) {
        if (auth == null || auth.config() == null || carrier == null) return;
        FriendlyByteBuf buf = new FriendlyByteBuf(io.netty.buffer.Unpooled.buffer());
        try {
            buf.writeBytes(ProxyProtocol.encodeSignedBackend(auth.config().proxySharedSecret(),
                auth.config().proxyBackendId(), ProxyProtocol.PREMIUM_SET, playerName));
            ServerPlayNetworking.send(carrier, CHANNEL, buf);
        }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy message", e); }
    }
}
