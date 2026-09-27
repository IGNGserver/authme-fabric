package io.github.authme.platform.folia;

import io.github.authme.platform.paper.PaperAuthCommand;
import io.github.authme.platform.paper.PaperAuthListener;
import io.github.authme.platform.paper.PaperAuthRuntime;
import io.github.authme.platform.paper.PaperPreJoinDialogListener;
import io.github.authme.platform.paper.PlatformScheduler;
import io.papermc.paper.threadedregions.scheduler.ScheduledTask;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.concurrent.TimeUnit;

/** Folia entrypoint with entity/global scheduler routing instead of Bukkit main-thread calls. */
public final class AuthMeFoliaPlugin extends JavaPlugin {

    private PaperAuthRuntime runtime;
    private PaperPreJoinDialogListener preJoinDialogListener;
    private Object placeholderExpansion;

    @Override
    public void onEnable() {
        try {
            runtime = PaperAuthRuntime.start(this, new FoliaScheduler(this));
        } catch (Exception exception) {
            getLogger().severe("AuthMe could not start safely: " + exception.getMessage());
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        getServer().getPluginManager().registerEvents(new PaperAuthListener(runtime), this);
        preJoinDialogListener = new PaperPreJoinDialogListener(runtime);
        getServer().getPluginManager().registerEvents(preJoinDialogListener, this);
        try {
            placeholderExpansion = io.github.authme.platform.paper.PaperPlaceholderHook.register(this, runtime);
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
        getLogger().info("AuthMe Folia bridge enabled with " + runtime.config().backend() + " storage.");
    }

    @Override
    public void onDisable() {
        if (placeholderExpansion != null) io.github.authme.platform.paper.PaperPlaceholderHook.unregister(placeholderExpansion);
        if (preJoinDialogListener != null) preJoinDialogListener.close();
        if (runtime != null) runtime.close();
    }

    private static final class FoliaScheduler implements PlatformScheduler {
        private final JavaPlugin plugin;

        private FoliaScheduler(JavaPlugin plugin) { this.plugin = plugin; }

        @Override
        public void runAsync(Runnable task) {
            Bukkit.getAsyncScheduler().runNow(plugin, ignored -> task.run());
        }

        @Override
        public boolean runForPlayer(Player player, Runnable task) {
            return player.getScheduler().run(plugin, ignored -> task.run(), null) != null;
        }

        @Override
        public void runGlobal(Runnable task) {
            Bukkit.getGlobalRegionScheduler().run(plugin, ignored -> task.run());
        }

        @Override
        public void runDelayedForPlayer(Player player, Runnable task, long delayTicks) {
            player.getScheduler().runDelayed(plugin, ignored -> task.run(), null, delayTicks);
        }

        @Override
        public void runDelayedGlobal(Runnable task, long delayTicks) {
            Bukkit.getGlobalRegionScheduler().runDelayed(plugin, ignored -> task.run(), delayTicks);
        }
    }
}
