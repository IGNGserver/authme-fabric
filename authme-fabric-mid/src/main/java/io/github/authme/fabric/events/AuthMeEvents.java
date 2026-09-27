package io.github.authme.fabric.events;

import io.github.authme.fabric.AuthMe;
import net.fabricmc.fabric.api.entity.event.v1.ServerLivingEntityEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerEntityEvents;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerTickEvents;
import net.fabricmc.fabric.api.event.player.AttackBlockCallback;
import net.fabricmc.fabric.api.event.player.AttackEntityCallback;
import net.fabricmc.fabric.api.event.player.UseBlockCallback;
import net.fabricmc.fabric.api.event.player.UseEntityCallback;
import net.fabricmc.fabric.api.event.player.UseItemCallback;
import net.fabricmc.fabric.api.message.v1.ServerMessageEvents;
import net.fabricmc.fabric.api.networking.v1.ServerPlayConnectionEvents;
import net.minecraft.core.BlockPos;
import net.minecraft.core.Direction;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.world.InteractionHand;
import net.minecraft.world.InteractionResult;
import net.minecraft.world.damagesource.DamageSource;
import net.minecraft.world.entity.Entity;
import net.minecraft.world.entity.LivingEntity;
import net.minecraft.world.entity.player.Player;
import net.minecraft.world.level.Level;
import net.minecraft.world.phys.BlockHitResult;
import net.minecraft.world.phys.EntityHitResult;

/**
 * Registers all Fabric API events used by the port: join/disconnect, per-tick (freeze, timeouts,
 * prompts), chat blocking, and interaction/damage blocking for unauthenticated players.
 */
public final class AuthMeEvents {

    private AuthMeEvents() {
    }

    public static void register() {
        ServerPlayConnectionEvents.JOIN.register((listener, sender, server) -> {
            ServerPlayer p = listener.getPlayer();
            AuthMe am = AuthMe.get();
            if (am != null && am.authManager() != null && p != null) {
                am.authManager().handleVipJoin(p);
                am.authManager().onJoin(p);
            }
        });

        ServerPlayConnectionEvents.DISCONNECT.register((listener, server) -> {
            ServerPlayer p = listener.getPlayer();
            AuthMe am = AuthMe.get();
            if (am != null && am.authManager() != null && p != null) am.authManager().onDisconnect(p);
        });

        ServerTickEvents.END_SERVER_TICK.register((MinecraftServer server) -> {
            AuthMe am = AuthMe.get();
            if (am != null && am.authManager() != null) {
                am.authManager().tick();
            }
        });

        ServerEntityEvents.ENTITY_LOAD.register((entity, world) -> {
            AuthMe am = AuthMe.get();
            if (am != null && am.authManager() != null) {
                am.authManager().trackLimboEnderPearl(entity, world);
            }
        });

        ServerMessageEvents.ALLOW_CHAT_MESSAGE.register((message, sender, boundChatType) -> {
            AuthMe am = AuthMe.get();
            if (am != null && am.authManager() != null && sender != null && am.authManager().isUnauthenticated(sender)
                && !am.authManager().allowChatBeforeLogin(sender)) {
                return false;
            }
            return true;
        });

        AttackBlockCallback.EVENT.register((player, level, hand, pos, direction) ->
            block(player) ? InteractionResult.FAIL : InteractionResult.PASS);

        UseBlockCallback.EVENT.register((player, level, hand, hitResult) ->
            block(player) && !unrestrictedBlock(player, level, hitResult.getBlockPos())
                ? InteractionResult.FAIL : InteractionResult.PASS);

        UseItemCallback.EVENT.register((player, level, hand) ->
            block(player) ? InteractionResult.FAIL : InteractionResult.PASS);

        AttackEntityCallback.EVENT.register((player, level, hand, entity, hitResult) ->
            block(player) ? InteractionResult.FAIL : InteractionResult.PASS);

        UseEntityCallback.EVENT.register((player, level, hand, entity, hitResult) ->
            block(player) && !unrestrictedEntity(player, entity)
                ? InteractionResult.FAIL : InteractionResult.PASS);

        ServerLivingEntityEvents.ALLOW_DAMAGE.register((entity, source, amount) -> {
            AuthMe am = AuthMe.get();
            return !(am != null && am.authManager() != null
                && entity instanceof ServerPlayer sp && am.authManager().isUnauthenticated(sp));
        });
    }

    private static boolean block(Player player) {
        AuthMe am = AuthMe.get();
        return am != null && am.authManager() != null
            && player instanceof ServerPlayer sp && am.authManager().isUnauthenticated(sp);
    }

    private static boolean unrestrictedBlock(Player player, Object level, BlockPos pos) {
        AuthMe am = AuthMe.get();
        return am != null && am.authManager() != null && player instanceof ServerPlayer sp
            && am.authManager().allowUnrestrictedBlock(sp, level, pos);
    }

    private static boolean unrestrictedEntity(Player player, Entity entity) {
        AuthMe am = AuthMe.get();
        return am != null && am.authManager() != null && player instanceof ServerPlayer sp
            && am.authManager().allowUnrestrictedEntity(sp, entity);
    }
}
