package io.github.authme.fabric.mixin;

import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.util.PermissionBridge;

import net.minecraft.server.players.NameAndId;
import net.minecraft.server.players.PlayerList;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Implements AuthMe's {@code authme.vip} full-server entry point without weakening vanilla's
 * ban, whitelist, IP-ban, or duplicate-login checks. Vanilla delegates only the capacity branch
 * of {@code canPlayerLogin} to {@code canBypassPlayerLimit}; the join handler then evicts one
 * non-VIP player to make the slot available.
 */
@Mixin(PlayerList.class)
public abstract class VipSlotMixin {

    @Inject(method = "canBypassPlayerLimit(Lnet/minecraft/server/players/NameAndId;)Z",
        at = @At("RETURN"), cancellable = true)
    private void authme$allowVip(NameAndId profile, CallbackInfoReturnable<Boolean> cir) {
        if (!cir.getReturnValueZ() && authme$hasVip(profile == null ? null : profile.id())) {
            cir.setReturnValue(true);
        }
    }

    private static boolean authme$hasVip(java.util.UUID uuid) {
        AuthMe auth = AuthMe.get();
        return auth != null && auth.config() != null && auth.config().permissionCheckEnabled()
            && Boolean.TRUE.equals(PermissionBridge.check(uuid, "authme.vip"));
    }
}
