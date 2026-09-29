package io.github.authme.platform.paper;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

/** Paper 1.21.11 entrypoint. */
public final class AuthMePaperPlugin extends JavaPlugin {

    private PaperAuthRuntime runtime;
    private PaperPreJoinDialogListener preJoinDialogListener;
    private Object placeholderExpansion;

    @Override
    public void onEnable() {
        try {
            runtime = PaperAuthRuntime.start(this, new PaperScheduler(this));
        } catch (Exception exception) {
            getLogger().severe("AuthMe could not start safely: " + exception.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        PaperAuthListener listener = new PaperAuthListener(runtime);
        getServer().getPluginManager().registerEvents(listener, this);
        preJoinDialogListener = new PaperPreJoinDialogListener(runtime);
        getServer().getPluginManager().registerEvents(preJoinDialogListener, this);
        try {
            placeholderExpansion = PaperPlaceholderHook.register(this, runtime);
            if (placeholderExpansion != null) getLogger().info("PlaceholderAPI expansion registered.");
        } catch (LinkageError | RuntimeException exception) {
            getLogger().warning("PlaceholderAPI was detected but its optional bridge could not load: "
                + exception.getClass().getSimpleName());
        }
        PaperAuthCommand command = new PaperAuthCommand(runtime);
        for (String name : new String[] {"authme", "login", "l", "register", "reg", "logout", "unregister", "changepassword", "changepass", "2fa", "totp", "captcha", "verification", "email", "premium", "freemium"}) {
            if (getCommand(name) != null) {
                getCommand(name).setExecutor(command);
                getCommand(name).setTabCompleter(command);
            }
        }
        getLogger().info("AuthMe Paper bridge enabled with " + runtime.config().backend() + " storage.");
    }

    @Override
    public void onDisable() {
        if (placeholderExpansion != null) PaperPlaceholderHook.unregister(placeholderExpansion);
        if (preJoinDialogListener != null) preJoinDialogListener.close();
        if (runtime != null) runtime.close();
    }

    private static final class PaperScheduler implements PlatformScheduler {
        private final JavaPlugin plugin;

        private PaperScheduler(JavaPlugin plugin) { this.plugin = plugin; }

        @Override
        public void runAsync(Runnable task) { Bukkit.getScheduler().runTaskAsynchronously(plugin, task); }

        @Override
        public boolean runForPlayer(Player player, Runnable task) {
            Bukkit.getScheduler().runTask(plugin, task);
            return true;
        }

        @Override
        public void runGlobal(Runnable task) { Bukkit.getScheduler().runTask(plugin, task); }

        @Override
        public void runDelayedForPlayer(Player player, Runnable task, long delayTicks) {
            Bukkit.getScheduler().runTaskLater(plugin, task, delayTicks);
        }

        @Override
        public void runDelayedGlobal(Runnable task, long delayTicks) {
            Bukkit.getScheduler().runTaskLater(plugin, task, delayTicks);
        }
    }
}
