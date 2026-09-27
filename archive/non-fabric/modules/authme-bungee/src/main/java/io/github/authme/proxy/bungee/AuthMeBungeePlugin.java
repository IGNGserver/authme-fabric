package io.github.authme.proxy.bungee;

import io.github.authme.proxy.core.ProxyConfig;
import net.md_5.bungee.api.ProxyServer;
import net.md_5.bungee.api.plugin.Command;
import net.md_5.bungee.api.plugin.Plugin;
import net.md_5.bungee.api.CommandSender;

import java.io.IOException;

/** Native BungeeCord/Waterfall AuthMe bridge plugin. */
public final class AuthMeBungeePlugin extends Plugin {

    private BungeeConfigManager configManager;
    private BungeeProxyBridge bridge;

    @Override
    public void onEnable() {
        configManager = new BungeeConfigManager(getDataFolder().toPath());
        try {
            ProxyConfig config = configManager.load();
            bridge = new BungeeProxyBridge(ProxyServer.getInstance(), this, getLogger(), config);
        } catch (IOException | RuntimeException exception) {
            getLogger().severe("Could not load AuthMe Bungee proxy configuration: " + exception.getMessage());
            return;
        }
        ProxyServer.getInstance().getPluginManager().registerListener(this, bridge);
        ProxyServer.getInstance().getPluginManager().registerCommand(this,
            new Command("authmeproxyreload", "authme.proxy.reload") {
            @Override
            public void execute(CommandSender sender, String[] args) {
                try {
                    bridge.reload(configManager.load());
                    sender.sendMessage("AuthMe proxy configuration reloaded.");
                } catch (IOException | RuntimeException exception) {
                    getLogger().severe("Could not reload AuthMe Bungee proxy configuration: " + exception.getMessage());
                    sender.sendMessage("AuthMe proxy reload failed.");
                }
            }
        });
        bridge.registerChannels();
        getLogger().info("AuthMe native Bungee proxy loaded");
    }

    @Override
    public void onDisable() {
        if (bridge != null) bridge.shutdown();
    }
}
