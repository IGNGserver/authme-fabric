package io.github.authme.fabric.util;

import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;

/**
 * Small helper around modern chat components. Ampersand colour codes in message strings are
 * converted to the Minecraft section-sign legacy codes, which clients render in chat, scoreboards
 * and the action bar.
 */
public final class MinecraftText {

    private static final char SECTION = '\u00a7';

    private MinecraftText() {
    }

    public static Component toComponent(String text) {
        return Component.literal(text == null ? "" : text.replace('&', SECTION));
    }

    public static void send(ServerPlayer player, String text) {
        if (player != null && text != null && !text.isEmpty()) {
            player.sendSystemMessage(toComponent(text));
        }
    }

    public static void sendActionBar(ServerPlayer player, String text) {
        if (player != null && text != null && !text.isEmpty()) {
            player.displayClientMessage(toComponent(text), true);
        }
    }
}