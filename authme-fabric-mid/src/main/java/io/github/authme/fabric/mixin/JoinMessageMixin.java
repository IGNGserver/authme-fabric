package io.github.authme.fabric.mixin;

import io.github.authme.fabric.network.JoinLeaveMessageBridge;
import net.minecraft.network.chat.Component;
import net.minecraft.server.players.PlayerList;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Redirect;

/** Filters vanilla's join broadcast when AuthMe needs to delay, replace, or remove it. */
@Mixin(PlayerList.class)
public abstract class JoinMessageMixin {

    @Redirect(method = "placeNewPlayer",
        at = @At(value = "INVOKE", target =
            "Lnet/minecraft/server/players/PlayerList;broadcastSystemMessage(Lnet/minecraft/network/chat/Component;Z)V"))
    private void authme$redirectJoin(PlayerList list, Component message, boolean overlay) {
        if (!JoinLeaveMessageBridge.shouldSuppressJoin()) {
            list.broadcastSystemMessage(message, overlay);
        }
    }
}
