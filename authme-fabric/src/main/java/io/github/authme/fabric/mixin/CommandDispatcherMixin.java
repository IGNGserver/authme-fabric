package io.github.authme.fabric.mixin;

import com.mojang.brigadier.ParseResults;
import com.mojang.brigadier.CommandDispatcher;

import io.github.authme.fabric.AuthMe;

import net.minecraft.commands.CommandSourceStack;
import net.minecraft.server.level.ServerPlayer;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfoReturnable;

/**
 * Cancels command execution for unauthenticated players except for an allow-list of auth-related
 * commands (configured by AuthMe). Targets the public Brigadier {@code execute(...)} entry points
 * so it intercepts every command dispatched through the registry, regardless of source.
 */
@Mixin(CommandDispatcher.class)
public class CommandDispatcherMixin {

    @Inject(method = "execute(Lcom/mojang/brigadier/ParseResults;)I", at = @At("HEAD"), cancellable = true)
    private void authme$onExecuteParsed(ParseResults<?> parse, CallbackInfoReturnable<Integer> cir) {
        if (shouldBlock(parse.getContext().getSource(), parse.getReader().getString())) {
            cir.setReturnValue(0);
        }
    }

    @Inject(method = "execute(Ljava/lang/String;Ljava/lang/Object;)I", at = @At("HEAD"), cancellable = true)
    private void authme$onExecuteString(String command, Object source, CallbackInfoReturnable<Integer> cir) {
        if (shouldBlock(source, command)) {
            cir.setReturnValue(0);
        }
    }

    private static boolean shouldBlock(Object source, String input) {
        AuthMe am = AuthMe.get();
        if (am == null || am.authManager() == null) return false;
        if (!(source instanceof CommandSourceStack css)) return false;
        if (!(css.getEntity() instanceof ServerPlayer player)) return false;
        if (am.authManager().isUnauthenticated(player)) {
            return !am.authManager().isCommandAllowed(player, rootToken(input));
        }
        return false;
    }

    private static String rootToken(String input) {
        if (input == null) return "";
        String s = input.trim();
        if (s.isEmpty()) return "";
        int space = s.indexOf(' ');
        String token = space < 0 ? s : s.substring(0, space);
        if (token.startsWith("/")) token = token.substring(1);
        return token;
    }
}