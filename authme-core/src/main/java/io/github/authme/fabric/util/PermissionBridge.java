package io.github.authme.fabric.util;

import java.lang.reflect.Method;
import java.util.UUID;
import java.util.function.Consumer;

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

    private PermissionBridge() {
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
}
