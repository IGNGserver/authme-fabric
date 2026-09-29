package io.github.authme.fabric.mixin;

import io.github.authme.fabric.AuthMe;
import net.minecraft.network.chat.ChatType;
import net.minecraft.network.chat.PlayerChatMessage;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.players.PlayerList;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.ModifyArg;

import java.util.function.Predicate;

/** Filters normal chat broadcasts from viewers who are still unauthenticated. */
@Mixin(PlayerList.class)
public abstract class ChatBroadcastMixin {

    @ModifyArg(
        method = "broadcastChatMessage(Lnet/minecraft/network/chat/PlayerChatMessage;Lnet/minecraft/server/level/ServerPlayer;Lnet/minecraft/network/chat/ChatType$Bound;)V",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/server/players/PlayerList;broadcastChatMessage(Lnet/minecraft/network/chat/PlayerChatMessage;Ljava/util/function/Predicate;Lnet/minecraft/server/level/ServerPlayer;Lnet/minecraft/network/chat/ChatType$Bound;)V"),
        index = 1,
        require = 1)
    private Predicate<ServerPlayer> authme$filterChatRecipients(Predicate<ServerPlayer> original) {
        AuthMe auth = AuthMe.get();
        if (auth == null || auth.authManager() == null || auth.config() == null || !auth.config().hideChat()) {
            return original;
        }
        return viewer -> original.test(viewer) && !auth.authManager().hideChatFrom(viewer);
    }
}
