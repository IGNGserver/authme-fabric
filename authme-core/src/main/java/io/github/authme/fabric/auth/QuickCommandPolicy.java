package io.github.authme.fabric.auth;

/**
 * Shared interpretation of AuthMe's quick-command permission.
 *
 * <p>The upstream node is an enable node: when permission checks are active, a
 * player must have it for the short post-join command guard to run. If no
 * optional permission provider is installed, the guard remains enabled rather
 * than silently failing open.</p>
 */
public final class QuickCommandPolicy {

    private QuickCommandPolicy() { }

    public static boolean enabled(boolean permissionCheckEnabled, boolean permissionGranted,
                                  boolean permissionProviderPresent) {
        if (!permissionCheckEnabled) return true;
        if (permissionGranted) return true;
        return !permissionProviderPresent;
    }
}
