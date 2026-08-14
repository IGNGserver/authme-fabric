package io.github.authme.fabric.mixin;

import io.github.authme.fabric.AuthMe;

import net.minecraft.network.protocol.game.ServerboundContainerClickPacket;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/**
 * Blocks inventory-click packets from unauthenticated players. This prevents them from
 * picking/placing/swapping items in their own inventory, in chests, anvils, droppers, etc.
 * (the equivalent of AuthMeReloaded's "unauthenticated inventory protection" feature, which
 * the upstream plugin implements via PacketEvents). Cancelling the entire handler is sufficient
 * and safe — vanilla only mutates server state inside {@code handleContainerClick}.
 */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class ContainerClickMixin {

    @Shadow
    public abstract ServerPlayer getPlayer();

    @Inject(method = "handleContainerClick", at = @At("HEAD"), cancellable = true)
    private void authme$onContainerClick(ServerboundContainerClickPacket packet, CallbackInfo ci) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null) return;
        ServerPlayer player = getPlayer();
        if (player == null) return;
        if (am.config().protectInventoryBeforeLogin() && am.authManager().isUnauthenticated(player)) {
            ci.cancel();
        }
    }
}
