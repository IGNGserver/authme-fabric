package io.github.authme.fabric.mixin;

import io.github.authme.fabric.network.JoinLeaveMessageBridge;
import net.minecraft.network.chat.Component;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import net.minecraft.server.players.PlayerList;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Filters vanilla's leave broadcast according to AuthMe's leave-message settings. */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class LeaveMessageMixin {

    @Shadow public ServerPlayer player;

    @Inject(method = "removePlayerFromWorld", at = @At("HEAD"))
    private void authme$captureDisconnect(CallbackInfo info) {
        JoinLeaveMessageBridge.beginDisconnect(player);
    }

    @Inject(method = "removePlayerFromWorld", at = @At("RETURN"))
    private void authme$clearDisconnect(CallbackInfo info) {
        JoinLeaveMessageBridge.endDisconnect();
    }

    @Redirect(method = "removePlayerFromWorld",
        at = @At(value = "INVOKE", target =
            "Lnet/minecraft/server/players/PlayerList;broadcastSystemMessage(Lnet/minecraft/network/chat/Component;Z)V"))
    private void authme$redirectLeave(PlayerList list, Component message, boolean overlay) {
        if (!JoinLeaveMessageBridge.shouldSuppressLeave(player)) {
            list.broadcastSystemMessage(message, overlay);
        }
    }
}
