package io.github.authme.fabric.util;

import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.server.players.PlayerList;
import net.minecraft.server.level.ServerLevel;
import net.minecraft.server.level.ServerPlayer;
import net.minecraft.commands.CommandSourceStack;
import net.minecraft.commands.Commands;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Array;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

/**
 * Small reflective boundary for the 1.19.3/1.19.4 Mojang-mapping drift.
 *
 * <p>The legacy adapter is compiled twice against two different Minecraft APIs. Keeping the
 * version-dependent calls here prevents the authentication state machine from having separate
 * security implementations for the two artifacts.</p>
 */
public final class MinecraftCompat {

    private MinecraftCompat() {
    }

    public static ServerLevel serverLevel(ServerPlayer player) {
        if (player == null) return null;
        for (String methodName : new String[]{"serverLevel", "getLevel", "level"}) {
            try {
                Method method = player.getClass().getMethod(methodName);
                Object value = method.invoke(player);
                if (value instanceof ServerLevel level) return level;
            } catch (ReflectiveOperationException | RuntimeException ignored) {
                // Try the next mapping name.
            }
        }
        return null;
    }

    public static boolean teleport(ServerPlayer player, double x, double y, double z,
                                   float yaw, float pitch) {
        ServerLevel level = serverLevel(player);
        if (level == null) return false;
        try {
            Method modern = player.getClass().getMethod("teleportTo", ServerLevel.class,
                double.class, double.class, double.class, Set.class, float.class, float.class);
            Object result = modern.invoke(player, level, x, y, z, Set.of(), yaw, pitch);
            return !(result instanceof Boolean) || (Boolean) result;
        } catch (NoSuchMethodException ignored) {
            try {
                Method old = player.getClass().getMethod("teleportTo", ServerLevel.class,
                    double.class, double.class, double.class, float.class, float.class);
                old.invoke(player, level, x, y, z, yaw, pitch);
                return true;
            } catch (ReflectiveOperationException | RuntimeException failure) {
                return false;
            }
        } catch (ReflectiveOperationException | RuntimeException failure) {
            return false;
        }
    }

    public static void sendSuccess(CommandSourceStack source, Component component, boolean broadcast) {
        try {
            Method modern = source.getClass().getMethod("sendSuccess", Supplier.class, boolean.class);
            modern.invoke(source, (Supplier<Component>) () -> component, broadcast);
            return;
        } catch (NoSuchMethodException ignored) {
            // 1.19.3 accepts the component directly.
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return;
        }
        try {
            Method old = source.getClass().getMethod("sendSuccess", Component.class, boolean.class);
            old.invoke(source, component, broadcast);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Command output must not be allowed to break the authentication command tree.
        }
    }

    /** Executes a configured command across the 1.18.2/1.19.3 method rename. */
    public static void performCommand(Commands commands, CommandSourceStack source, String command) {
        if (commands == null || source == null || command == null) return;
        try {
            Method modern = commands.getClass().getMethod("performPrefixedCommand",
                CommandSourceStack.class, String.class);
            modern.invoke(commands, source, command);
            return;
        } catch (NoSuchMethodException ignored) {
            // 1.18.2 calls the same operation performCommand.
        } catch (ReflectiveOperationException | RuntimeException failure) {
            throw new IllegalStateException("Configured command execution failed", failure);
        }
        try {
            Method old = commands.getClass().getMethod("performCommand",
                CommandSourceStack.class, String.class);
            old.invoke(commands, source, command);
        } catch (ReflectiveOperationException | RuntimeException failure) {
            throw new IllegalStateException("Configured command execution failed", failure);
        }
    }

    /** Creates the vanilla join component across the old and new Component APIs. */
    public static MutableComponent joinMessage(ServerPlayer player) {
        if (player == null) return null;
        Object[] arguments = new Object[]{player.getDisplayName()};
        try {
            Method factory = Component.class.getMethod("translatable", String.class, Object[].class);
            Object value = factory.invoke(null, new Object[]{"multiplayer.player.joined", arguments});
            if (value instanceof MutableComponent component) return component;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // 1.18.2 uses TranslatableComponent instead of static factories.
        }
        try {
            Class<?> type = Class.forName("net.minecraft.network.chat.TranslatableComponent");
            Constructor<?> constructor = type.getConstructor(String.class, Object[].class);
            Object value = constructor.newInstance(new Object[]{"multiplayer.player.joined", arguments});
            if (value instanceof MutableComponent component) return component;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return null;
        }
        return null;
    }

    /** Broadcasts a system message across the old ChatType and new boolean APIs. */
    public static void broadcastSystemMessage(PlayerList list, Component message, boolean overlay) {
        if (list == null || message == null) return;
        try {
            Method modern = list.getClass().getMethod("broadcastSystemMessage", Component.class, boolean.class);
            modern.invoke(list, message, overlay);
            return;
        } catch (NoSuchMethodException ignored) {
            // 1.18.2 uses broadcastMessage(Component, ChatType, UUID).
        } catch (ReflectiveOperationException | RuntimeException failure) {
            return;
        }
        try {
            Class<?> chatType = Class.forName("net.minecraft.network.chat.ChatType");
            Object system = chatType.getField("SYSTEM").get(null);
            Method old = list.getClass().getMethod("broadcastMessage", Component.class, chatType, UUID.class);
            old.invoke(list, message, system, new UUID(0L, 0L));
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Message cosmetics must never break authentication or disconnect handling.
        }
    }

    /**
     * Hides a player from one tab list across the 1.19.2 and 1.19.3 packet API
     * split.  Reflection is kept at this narrow boundary so the shared
     * authentication state machine can be compiled against both mappings.
     */
    public static void removeTabEntry(ServerPlayer viewer, ServerPlayer subject) {
        if (viewer == null || subject == null) return;
        UUID playerId = subject.getUUID();
        try {
            Class<?> packet = Class.forName("net.minecraft.network.protocol.game.ClientboundPlayerInfoRemovePacket");
            Constructor<?> constructor = packet.getConstructor(List.class);
            sendPacket(viewer, constructor.newInstance(List.of(playerId)));
            return;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // 1.19.2 uses ClientboundPlayerInfoPacket with an Action value.
        }
        Object packet = legacyPlayerInfoPacket("REMOVE_PLAYER", List.of(subject));
        if (packet != null) sendPacket(viewer, packet);
    }

    /** Adds a player to one tab list across the modern and pre-1.19.3 packet APIs. */
    public static void addTabEntry(ServerPlayer viewer, ServerPlayer subject) {
        if (viewer == null || subject == null) return;
        try {
            Class<?> packet = Class.forName("net.minecraft.network.protocol.game.ClientboundPlayerInfoUpdatePacket");
            Class<?> action = Class.forName(packet.getName() + "$Action");
            Object add = action.getField("ADD_PLAYER").get(null);
            for (Constructor<?> constructor : packet.getConstructors()) {
                Class<?>[] types = constructor.getParameterTypes();
                if (types.length == 2 && Collection.class.isAssignableFrom(types[1])) {
                    @SuppressWarnings({"rawtypes", "unchecked"})
                    java.util.EnumSet actions = java.util.EnumSet.noneOf((Class) action);
                    actions.add(add);
                    sendPacket(viewer, constructor.newInstance(actions, List.of(subject)));
                    return;
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Fall through to the 1.19.2 packet shape.
        }
        Object packet = legacyPlayerInfoPacket("ADD_PLAYER", List.of(subject));
        if (packet != null) sendPacket(viewer, packet);
    }

    private static Object legacyPlayerInfoPacket(String actionName, List<?> entries) {
        try {
            Class<?> packet = Class.forName("net.minecraft.network.protocol.game.ClientboundPlayerInfoPacket");
            Class<?> actionType = Class.forName(packet.getName() + "$Action");
            Field field = actionType.getField(actionName);
            Object action = field.get(null);
            for (Constructor<?> constructor : packet.getConstructors()) {
                Class<?>[] types = constructor.getParameterTypes();
                if (types.length != 2 || !types[0].isAssignableFrom(action.getClass())) continue;
                if (Collection.class.isAssignableFrom(types[1])) {
                    return constructor.newInstance(action, entries);
                }
                if (types[1].isArray()) {
                    Object array = Array.newInstance(types[1].getComponentType(), entries.size());
                    for (int i = 0; i < entries.size(); i++) Array.set(array, i, entries.get(i));
                    return constructor.newInstance(action, array);
                }
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // Version-specific tab-list filtering is best effort; auth state does not depend on it.
        }
        return null;
    }

    private static void sendPacket(ServerPlayer viewer, Object packet) {
        if (packet == null) return;
        try {
            Class<?> packetType = Class.forName("net.minecraft.network.protocol.Packet");
            Method send = viewer.connection.getClass().getMethod("send", packetType);
            send.invoke(viewer.connection, packet);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // The tab-list cosmetic must never affect authentication or disconnects.
        }
    }
}
