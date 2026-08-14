package io.github.authme.fabric.mixin;

import io.github.authme.fabric.AuthMe;
import net.minecraft.network.protocol.game.ServerboundCommandSuggestionPacket;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.server.network.ServerGamePacketListenerImpl;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

/** Prevents command-name/player-name enumeration before authentication when configured. */
@Mixin(ServerGamePacketListenerImpl.class)
public abstract class CommandSuggestionMixin {

    @Shadow
    public abstract ServerPlayer getPlayer();

    @Inject(method = "handleCustomCommandSuggestions", at = @At("HEAD"), cancellable = true)
    private void authme$denyUnauthenticatedSuggestions(ServerboundCommandSuggestionPacket packet, CallbackInfo ci) {
        AuthMe am = AuthMe.get();
        if (am != null && am.authManager() != null && am.config().denyTabCompleteBeforeLogin()
            && am.authManager().isUnauthenticated(getPlayer())) ci.cancel();
    }
}
