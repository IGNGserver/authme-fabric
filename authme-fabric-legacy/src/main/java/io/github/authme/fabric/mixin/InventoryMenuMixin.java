package io.github.authme.fabric.mixin;

import io.github.authme.fabric.AuthMe;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.MenuProvider;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

import java.util.OptionalInt;

/** Captures the title and id of a successfully opened menu for the inventory exception. */
@Mixin(ServerPlayer.class)
public abstract class InventoryMenuMixin {

    @Inject(method = "openMenu", at = @At("RETURN"))
    private void authme$recordOpen(MenuProvider provider, CallbackInfoReturnable<OptionalInt> cir) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null) return;
        ServerPlayer player = (ServerPlayer) (Object) this;
        OptionalInt result = cir.getReturnValue();
        if (result.isPresent() && provider != null) {
            am.authManager().recordInventoryOpen(player, result.getAsInt(),
                provider.getDisplayName().getString());
        } else {
            am.authManager().clearInventoryOpen(player);
        }
    }

    @Inject(method = "doCloseContainer", at = @At("HEAD"))
    private void authme$clearClose(CallbackInfo ci) {
        AuthMe am = AuthMe.get();
        if (am != null && am.authManager() != null) {
            am.authManager().clearInventoryOpen((ServerPlayer) (Object) this);
        }
    }
}
