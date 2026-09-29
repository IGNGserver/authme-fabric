package io.github.authme.platform.spigot.legacy;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;

/** Spigot 1.16.5-1.19.3 compatible entrypoint using only the legacy Bukkit event surface. */
public final class AuthMeSpigotLegacyPlugin extends JavaPlugin {

    private LegacyAuthRuntime runtime;
    private Object placeholderExpansion;

    @Override
    public void onEnable() {
        try {
            runtime = LegacyAuthRuntime.start(this);
        } catch (Exception exception) {
            getLogger().severe("AuthMe could not start safely: " + exception.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        getServer().getPluginManager().registerEvents(new LegacyAuthListener(runtime), this);
        try {
            placeholderExpansion = LegacyPlaceholderHook.register(this, runtime);
            if (placeholderExpansion != null) getLogger().info("PlaceholderAPI expansion registered.");
        } catch (LinkageError | RuntimeException exception) {
            getLogger().warning("PlaceholderAPI was detected but its optional bridge could not load: "
                + exception.getClass().getSimpleName());
        }
        LegacyAuthCommand command = new LegacyAuthCommand(runtime);
        for (String name : new String[] {"authme", "login", "l", "register", "reg", "logout", "unregister", "changepassword", "changepass", "2fa", "totp", "captcha", "verification", "email", "premium", "freemium"}) {
            if (getCommand(name) != null) {
                getCommand(name).setExecutor(command);
                getCommand(name).setTabCompleter(command);
            }
        }
        getLogger().info("AuthMe legacy Spigot bridge enabled with " + runtime.config().backend() + " storage.");
    }

    @Override
    public void onDisable() {
        if (placeholderExpansion != null) LegacyPlaceholderHook.unregister(placeholderExpansion);
        if (runtime != null) runtime.close();
    }
}
