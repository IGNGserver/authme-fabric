package io.github.authme.fabric.network;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.ProxyProtocol;
import net.fabricmc.fabric.api.networking.v1.ServerPlayNetworking;
import net.minecraft.network.FriendlyByteBuf;
import net.minecraft.resources.ResourceLocation;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;

import java.util.concurrent.CompletableFuture;

/** Secure raw-channel AuthMe proxy bridge for Minecraft 1.19.4–1.20.4. */
public final class ProxyBridge {
    private static final ResourceLocation CHANNEL = new ResourceLocation("authme", "main");
    private static final ResourceLocation BUNGEE_CHANNEL = new ResourceLocation("bungeecord", "main");
    private ProxyBridge() { }

    public static void register() {
        ServerPlayNetworking.registerGlobalReceiver(CHANNEL, (server, player, handler, buf, responseSender) -> {
            byte[] data = new byte[buf.readableBytes()];
            buf.readBytes(data);
            server.execute(() -> handle(server, player, data));
        });
    }

    public static void bind(AuthMe auth, MinecraftServer server) {
        auth.setProxyMessageSink((type, name) -> send(server, type, name));
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
            .filter(p -> p.getGameProfile().getName().equalsIgnoreCase(playerName)).findFirst()
            .orElseGet(() -> server.getPlayerList().getPlayers().stream().findFirst().orElse(null));
        if (carrier == null) return;
        FriendlyByteBuf buf = new FriendlyByteBuf(io.netty.buffer.Unpooled.buffer());
        buf.writeBytes(ProxyProtocol.encode(type, playerName));
        try { ServerPlayNetworking.send(carrier, CHANNEL, buf); }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy message", e); }
    }

    private static void sendTo(ServerPlayer carrier, String playerName) {
        FriendlyByteBuf buf = new FriendlyByteBuf(io.netty.buffer.Unpooled.buffer());
        buf.writeBytes(ProxyProtocol.encode(ProxyProtocol.PREMIUM_SET, playerName));
        try { ServerPlayNetworking.send(carrier, CHANNEL, buf); }
        catch (RuntimeException e) { Log.error("Could not send AuthMe proxy state update", e); }
    }
}
