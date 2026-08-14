package io.github.authme.fabric.network;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.MinecraftText;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/** Implements the AuthMe join/leave message switches around vanilla's broadcasts. */
public final class JoinLeaveMessageBridge {

    private static final Map<UUID, Component> PENDING_JOIN_MESSAGES = new ConcurrentHashMap<>();
    private static final ThreadLocal<ServerPlayer> DISCONNECTING_PLAYER = new ThreadLocal<>();

    private JoinLeaveMessageBridge() {
    }

    public static boolean shouldSuppressJoin() {
        AuthMe auth = AuthMe.get();
        if (auth == null || auth.config() == null) return false;
        return auth.config().removeJoinMessage()
            || auth.config().delayJoinMessage()
            || !auth.config().customJoinMessage().isBlank();
    }

    /** Called from the AuthMe join path after vanilla has created the player. */
    public static void prepareJoin(ServerPlayer player) {
        AuthMe auth = AuthMe.get();
        if (player == null || auth == null || auth.config() == null
            || auth.config().removeJoinMessage()
            || (!auth.config().delayJoinMessage() && auth.config().customJoinMessage().isBlank())) return;
        Component vanilla = Component.translatable("multiplayer.player.joined", player.getDisplayName())
            .withStyle(ChatFormatting.YELLOW);
        PENDING_JOIN_MESSAGES.put(player.getUUID(), vanilla);
    }

    /** Sends a delayed/custom join message only after successful authentication. */
    public static void onAuthenticated(ServerPlayer player) {
        if (player == null) return;
        Component vanilla = PENDING_JOIN_MESSAGES.remove(player.getUUID());
        if (vanilla == null) return;
        AuthMe auth = AuthMe.get();
        if (auth == null || auth.config() == null || auth.config().removeJoinMessage()) return;
        String custom = auth.config().customJoinMessage();
        Component message = custom.isBlank() ? vanilla
            : MinecraftText.toComponent(renderCustom(custom, player));
        if (auth.server() != null) {
            auth.server().getPlayerList().broadcastSystemMessage(message, false);
        }
    }

    public static void clear(ServerPlayer player) {
        if (player != null) PENDING_JOIN_MESSAGES.remove(player.getUUID());
    }

    private static String renderCustom(String value, ServerPlayer player) {
        String name = player.getGameProfile().name();
        String display = player.getDisplayName().getString();
        return value.replace("{PLAYERNAME}", name)
            .replace("{DISPLAYNAME}", display)
            .replace("{DISPLAYNAMENOCOLOR}", display)
            .replace("{PLAYER}", name);
    }

    public static void beginDisconnect(ServerPlayer player) {
        DISCONNECTING_PLAYER.set(player);
    }

    public static void endDisconnect() {
        DISCONNECTING_PLAYER.remove();
    }

    public static boolean shouldSuppressLeave(ServerPlayer fallback) {
        AuthMe auth = AuthMe.get();
        if (auth == null || auth.config() == null) return false;
        if (auth.config().removeLeaveMessage()) return true;
        if (!auth.config().removeUnloggedLeaveMessage()) return false;
        ServerPlayer player = DISCONNECTING_PLAYER.get();
        if (player == null) player = fallback;
        return player != null && auth.authManager() != null
            && !auth.authManager().isAuthenticated(player);
    }
}
