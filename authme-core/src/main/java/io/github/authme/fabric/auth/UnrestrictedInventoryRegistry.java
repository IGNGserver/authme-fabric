package io.github.authme.fabric.auth;

import java.util.Collection;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Tracks the currently open custom inventory for unauthenticated players.
 *
 * <p>The client only sends a container id with a click packet, so the title has
 * to be captured when {@code ServerPlayer.openMenu} succeeds. The registry is
 * deliberately scoped to one AuthManager and is cleared on join/disconnect;
 * a stale container id must never grant access to a later session.</p>
 */
public final class UnrestrictedInventoryRegistry {

    private final ConcurrentMap<UUID, OpenedInventory> open = new ConcurrentHashMap<>();

    public void record(UUID uuid, int containerId, String title) {
        if (uuid == null || containerId < 0 || title == null || title.isBlank()) {
            clear(uuid);
            return;
        }
        open.put(uuid, new OpenedInventory(containerId, normalize(title)));
    }

    public boolean allows(UUID uuid, int containerId, Collection<String> configuredTitles) {
        if (uuid == null || containerId < 0 || configuredTitles == null || configuredTitles.isEmpty()) {
            return false;
        }
        OpenedInventory opened = open.get(uuid);
        return opened != null && opened.containerId() == containerId
            && matches(opened.title(), configuredTitles);
    }

    public void clear(UUID uuid) {
        if (uuid != null) open.remove(uuid);
    }

    public void clearAll() {
        open.clear();
    }

    public static boolean matches(String title, Collection<String> configuredTitles) {
        if (title == null || configuredTitles == null) return false;
        String normalized = normalize(title);
        for (String configured : configuredTitles) {
            if (configured != null && normalized.equals(normalize(configured))) return true;
        }
        return false;
    }

    private static String normalize(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private record OpenedInventory(int containerId, String title) { }
}
