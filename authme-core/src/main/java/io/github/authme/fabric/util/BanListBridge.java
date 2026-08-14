package io.github.authme.fabric.util;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/** Reads the vanilla player ban list without coupling the core to a versioned Minecraft class. */
public final class BanListBridge {

    private BanListBridge() {
    }

    /**
     * Returns the lowercase names currently present in the vanilla user-ban list.
     * Reflection is intentional: the underlying Mojang class moved methods between
     * supported Fabric/Minecraft lines, while the operation itself is stable.
     */
    public static Set<String> names(Object playerList) {
        Set<String> result = new LinkedHashSet<>();
        if (playerList == null) return result;
        try {
            Object bans = invokeNoArg(playerList, "getBans");
            if (bans == null) bans = invokeNoArg(playerList, "getBannedPlayers");
            if (bans == null) return result;

            Object users = invokeNoArg(bans, "getUserList");
            if (users instanceof String[] array) {
                for (String name : array) add(result, name);
            } else if (users instanceof Collection<?> collection) {
                for (Object value : collection) addEntry(result, value);
            }

            Object entries = invokeNoArg(bans, "getEntries");
            if (entries instanceof Collection<?> collection) {
                for (Object value : collection) addEntry(result, value);
            }
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // A missing/changed optional ban API must not make the authentication subsystem fail.
        }
        return result;
    }

    private static void addEntry(Set<String> result, Object entry) {
        if (entry == null) return;
        if (entry instanceof String name) {
            add(result, name);
            return;
        }
        Object user = invokeQuietly(entry, "getUser");
        if (user == null) user = invokeQuietly(entry, "getProfile");
        if (user != null) {
            Object name = invokeQuietly(user, "getName");
            if (name != null) add(result, String.valueOf(name));
        }
    }

    private static void add(Set<String> result, String value) {
        if (value != null && !value.isBlank()) result.add(value.trim().toLowerCase(Locale.ROOT));
    }

    private static Object invokeNoArg(Object target, String name) throws ReflectiveOperationException {
        for (Method method : target.getClass().getMethods()) {
            if (method.getName().equals(name) && method.getParameterCount() == 0) return method.invoke(target);
        }
        return null;
    }

    private static Object invokeQuietly(Object target, String name) {
        try {
            return invokeNoArg(target, name);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return null;
        }
    }
}
