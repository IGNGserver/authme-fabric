package io.github.authme.fabric.util;

import java.lang.reflect.Method;
import java.util.List;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;
import java.util.function.Consumer;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Optional bridge for permission-node providers on Fabric.
 *
 * <p>The vanilla command API only exposes operator levels.  When LuckPerms is
 * installed, this class also understands the AuthMe permission nodes without
 * making LuckPerms a hard dependency.  A missing provider, an unloaded user,
 * or an API mismatch deliberately returns {@code null}; callers can then use
 * the vanilla operator fallback.</p>
 */
public final class PermissionBridge {

    private static final AtomicBoolean GROUP_SWITCH_WARNING_LOGGED = new AtomicBoolean();

    private PermissionBridge() {
    }

    /** Opaque list of transient LuckPerms nodes owned by one AuthMe unauthenticated session. */
    public record GroupSnapshot(boolean applied, List<Object> nodes) {
        public GroupSnapshot {
            nodes = nodes == null ? List.of() : List.copyOf(nodes);
        }
    }

    /**
     * @return true/false when an optional provider made a decision, or null if
     * no provider is available or the user is not loaded yet
     */
    public static Boolean check(UUID uuid, String node) {
        if (uuid == null || node == null || node.isBlank()) return null;
        try {
            Class<?> provider = Class.forName("net.luckperms.api.LuckPermsProvider");
            Object luckPerms = provider.getMethod("get").invoke(null);
            Object users = invokeNoArg(luckPerms, "getUserManager");
            if (users == null) return null;
            Object user = invoke(users, "getUser", UUID.class, uuid);
            if (user == null) return null;
            Object cachedData = invokeNoArg(user, "getCachedData");
            if (cachedData == null) return null;
            Object permissionData = invokeNoArg(cachedData, "getPermissionData");
            if (permissionData == null) return null;
            Object result = invoke(permissionData, "checkPermission", String.class, node);
            if (result == null) return null;
            String value = result.toString().toUpperCase(java.util.Locale.ROOT);
            if (value.contains("TRUE")) return Boolean.TRUE;
            if (value.contains("FALSE")) return Boolean.FALSE;
            return null;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) {
            return null;
        }
    }

    /**
     * Distinguishes an absent optional permission provider from a provider that
     * is present but failed to answer. Player command checks may fall back to
     * the vanilla behavior only in the former case; treating provider errors
     * as allow would turn an integration outage into a privilege escalation.
     */
    public static boolean providerPresent() {
        try {
            Class.forName("net.luckperms.api.LuckPermsProvider");
            return true;
        } catch (ClassNotFoundException | LinkageError | RuntimeException ignored) {
            return false;
        }
    }

    /**
     * Best-effort LuckPerms group cleanup for the optional Purge bridge.
     * Returns null when LuckPerms is absent, true when a user was modified,
     * and false when the API was present but the operation was unavailable.
     */
    public static Boolean clearGroups(UUID uuid) {
        if (uuid == null) return false;
        try {
            Class<?> provider = Class.forName("net.luckperms.api.LuckPermsProvider");
            Object luckPerms = provider.getMethod("get").invoke(null);
            Object users = invokeNoArg(luckPerms, "getUserManager");
            if (users == null) return false;
            Method modifyUser = null;
            for (Method method : users.getClass().getMethods()) {
                if (method.getName().equals("modifyUser") && method.getParameterCount() == 2
                    && method.getParameterTypes()[0] == UUID.class) {
                    modifyUser = method;
                    break;
                }
            }
            if (modifyUser == null) return false;
            Consumer<Object> clear = user -> {
                try {
                    Object nodeMap = invokeNoArg(user, "data");
                    if (nodeMap != null) {
                        Method clearMethod = nodeMap.getClass().getMethod("clear");
                        clearMethod.invoke(nodeMap);
                    }
                } catch (ReflectiveOperationException | RuntimeException ignored) { }
            };
            modifyUser.invoke(users, uuid, clear);
            return true;
        } catch (ClassNotFoundException e) {
            return null;
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            return false;
        }
    }

    /**
     * Temporarily masks inherited groups and adds the configured unauthenticated group using
     * LuckPerms' transient node map. No persistent node is cleared or saved, so a crash cannot
     * overwrite the account's durable permissions and concurrent permission edits remain intact.
     */
    public static GroupSnapshot applyGroup(UUID uuid, String group) {
        if (uuid == null || group == null || group.isBlank()) return new GroupSnapshot(false, List.of());
        List<Object> owned = new ArrayList<>();
        try {
            Class<?> provider = Class.forName("net.luckperms.api.LuckPermsProvider");
            Object luckPerms = provider.getMethod("get").invoke(null);
            Object users = invokeNoArg(luckPerms, "getUserManager");
            Object user = users == null ? null : invoke(users, "getUser", UUID.class, uuid);
            Object transientData = user == null ? null : invokeNoArg(user, "transientData");
            Object queryOptions = user == null ? null : invokeNoArg(user, "getQueryOptions");
            if (user == null || transientData == null || queryOptions == null) return unavailableGroupSnapshot();

            Object inherited = invokeAssignable(user, "getInheritedGroups", queryOptions);
            if (!(inherited instanceof Collection<?> groups)) return unavailableGroupSnapshot();
            for (Object inheritedGroup : groups) {
                Object name = invokeNoArg(inheritedGroup, "getName");
                if (!(name instanceof String inheritedName)) {
                    removeTransientNodes(transientData, owned);
                    return unavailableGroupSnapshot();
                }
                if (inheritedName.equalsIgnoreCase(group)) continue;
                Object negative = inheritanceNode(inheritedName, false);
                if (addTransientNode(transientData, negative)) {
                    owned.add(negative);
                } else if (!containsExactNode(transientData, negative)) {
                    removeTransientNodes(transientData, owned);
                    return unavailableGroupSnapshot();
                }
            }

            Object temporary = inheritanceNode(group, true);
            if (!addTransientNode(transientData, temporary)) {
                // An identical transient node may already exist. Do not claim ownership of it,
                // but the requested group state is still active and can safely be used.
                if (!containsExactNode(transientData, temporary)) {
                    removeTransientNodes(transientData, owned);
                    return unavailableGroupSnapshot();
                }
            } else {
                owned.add(temporary);
            }
            return new GroupSnapshot(true, owned);
        } catch (ClassNotFoundException e) {
            return new GroupSnapshot(false, List.of());
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            tryRollback(uuid, owned);
            return unavailableGroupSnapshot();
        }
    }

    /**
     * Removes only transient nodes added by {@link #applyGroup}; persistent and third-party
     * transient nodes are never cleared or replayed.
     */
    public static boolean restoreGroup(UUID uuid, GroupSnapshot snapshot) {
        if (snapshot == null || !snapshot.applied() || snapshot.nodes().isEmpty()) return true;
        try {
            Class<?> provider = Class.forName("net.luckperms.api.LuckPermsProvider");
            Object luckPerms = provider.getMethod("get").invoke(null);
            Object users = invokeNoArg(luckPerms, "getUserManager");
            Object user = users == null ? null : invoke(users, "getUser", UUID.class, uuid);
            Object transientData = user == null ? null : invokeNoArg(user, "transientData");
            return transientData != null && removeTransientNodes(transientData, snapshot.nodes());
        } catch (ReflectiveOperationException | LinkageError | RuntimeException e) {
            return false;
        }
    }

    private static GroupSnapshot unavailableGroupSnapshot() {
        if (GROUP_SWITCH_WARNING_LOGGED.compareAndSet(false, true)) {
            Log.warn("LuckPerms is present but its transient group API was unavailable; AuthMe "
                + "did not modify persistent permission nodes");
        }
        return new GroupSnapshot(false, List.of());
    }

    private static Object inheritanceNode(String group, boolean value) throws ReflectiveOperationException {
        Class<?> type = Class.forName("net.luckperms.api.node.types.InheritanceNode");
        Object builder = type.getMethod("builder", String.class).invoke(null, group);
        Object valued = invoke(builder, "value", boolean.class, value);
        return invokeNoArg(valued == null ? builder : valued, "build");
    }

    private static boolean addTransientNode(Object transientData, Object node)
        throws ReflectiveOperationException {
        Object result = invokeAssignable(transientData, "add", node);
        Object successful = result == null ? null : invokeNoArg(result, "wasSuccessful");
        return Boolean.TRUE.equals(successful);
    }

    private static boolean containsExactNode(Object transientData, Object node)
        throws ReflectiveOperationException {
        Object contains = invokeAssignable(transientData, "contains", node,
            staticField("net.luckperms.api.node.NodeEqualityPredicate", "EXACT"));
        return Boolean.TRUE.equals(contains)
            || (contains != null && "TRUE".equalsIgnoreCase(contains.toString()));
    }

    private static boolean removeTransientNodes(Object transientData, Collection<?> nodes)
        throws ReflectiveOperationException {
        boolean ok = true;
        for (Object node : nodes) {
            Object result = invokeAssignable(transientData, "remove", node);
            Object successful = result == null ? null : invokeNoArg(result, "wasSuccessful");
            // FAIL_LACKS is an idempotent success: another unload/cleanup already removed it.
            if (!Boolean.TRUE.equals(successful)
                && (result == null || !result.toString().contains("FAIL_LACKS"))) ok = false;
        }
        return ok;
    }

    private static void tryRollback(UUID uuid, Collection<?> nodes) {
        if (nodes.isEmpty()) return;
        try {
            Class<?> provider = Class.forName("net.luckperms.api.LuckPermsProvider");
            Object luckPerms = provider.getMethod("get").invoke(null);
            Object users = invokeNoArg(luckPerms, "getUserManager");
            Object user = users == null ? null : invoke(users, "getUser", UUID.class, uuid);
            Object transientData = user == null ? null : invokeNoArg(user, "transientData");
            if (transientData != null) removeTransientNodes(transientData, nodes);
        } catch (ReflectiveOperationException | LinkageError | RuntimeException ignored) { }
    }

    private static Object staticField(String className, String name) throws ReflectiveOperationException {
        return Class.forName(className).getField(name).get(null);
    }

    private static Object invokeNoArg(Object target, String name) throws ReflectiveOperationException {
        for (Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 0) {
                return method.invoke(target);
            }
        }
        return null;
    }

    private static Object invoke(Object target, String name, Class<?> type, Object value)
        throws ReflectiveOperationException {
        for (Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 1
                && method.getParameterTypes()[0].isAssignableFrom(type)) {
                return method.invoke(target, value);
            }
        }
        return null;
    }

    private static Object invokeAssignable(Object target, String name, Object... values)
        throws ReflectiveOperationException {
        outer:
        for (Method method : target.getClass().getMethods()) {
            if (!method.getName().equals(name) || method.getParameterCount() != values.length) continue;
            Class<?>[] types = method.getParameterTypes();
            for (int i = 0; i < types.length; i++) {
                if (values[i] != null && !types[i].isInstance(values[i])) continue outer;
            }
            return method.invoke(target, values);
        }
        return null;
    }
}
