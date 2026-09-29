package io.github.authme.proxy.velocity;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandMeta;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.EventTask;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.DisconnectEvent;
import com.velocitypowered.api.event.connection.PluginMessageEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.player.GameProfileRequestEvent;
import com.velocitypowered.api.event.player.PlayerChatEvent;
import com.velocitypowered.api.event.player.ServerConnectedEvent;
import com.velocitypowered.api.event.player.ServerPreConnectEvent;
import com.velocitypowered.api.event.player.configuration.PlayerEnteredConfigurationEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.event.proxy.ProxyShutdownEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.ProxyServer;
import io.github.authme.proxy.core.ProxyConfig;
import org.slf4j.Logger;

import java.io.IOException;
import java.nio.file.Path;

@Plugin(id = "authme", name = "AuthMe Native Proxy", version = "6.0.1-fabric.2-SNAPSHOT",
    description = "Native Velocity bridge for AuthMe Fabric backends",
    authors = {"AuthMe"})
public final class AuthMeVelocityPlugin {

    private final ProxyServer proxy;
    private final Logger logger;
    private final Path dataDirectory;
    private final VelocityConfigManager configManager;
    private final VelocityProxyBridge bridge;

    @Inject
    public AuthMeVelocityPlugin(ProxyServer proxy, Logger logger, @DataDirectory Path dataDirectory) {
        this.proxy = proxy;
        this.logger = logger;
        this.dataDirectory = dataDirectory;
        this.configManager = new VelocityConfigManager(dataDirectory);
        try {
            this.bridge = new VelocityProxyBridge(proxy, logger, configManager.load());
        } catch (IOException | RuntimeException exception) {
            throw new IllegalStateException("Could not load AuthMe Velocity proxy configuration", exception);
        }
    }

    @Subscribe
    public void onProxyInitialize(ProxyInitializeEvent event) {
        bridge.registerChannels();
        CommandMeta meta = proxy.getCommandManager().metaBuilder("authmeproxyreload").plugin(this).build();
        proxy.getCommandManager().register(meta, new SimpleCommand() {
            @Override
            public void execute(Invocation invocation) {
                try {
                    bridge.reload(configManager.load());
                    invocation.source().sendMessage(net.kyori.adventure.text.Component.text("AuthMe proxy configuration reloaded."));
                } catch (IOException | RuntimeException exception) {
                    logger.error("Could not reload AuthMe proxy configuration", exception);
                    invocation.source().sendMessage(net.kyori.adventure.text.Component.text("AuthMe proxy reload failed."));
                }
            }

            @Override
            public boolean hasPermission(Invocation invocation) {
                return invocation.source().hasPermission("authme.proxy.reload");
            }
        });
        logger.info("AuthMe native Velocity proxy loaded");
    }

    @Subscribe public void onPluginMessage(PluginMessageEvent event) { bridge.onPluginMessage(event); }
    @Subscribe public EventTask onPreLogin(PreLoginEvent event) { return bridge.onPreLogin(event); }
    @Subscribe public void onGameProfileRequest(GameProfileRequestEvent event) { bridge.onGameProfileRequest(event); }
    @Subscribe public void onPlayerEnteredConfiguration(PlayerEnteredConfigurationEvent event) { bridge.onPlayerEnteredConfiguration(event); }
    @Subscribe public void onServerConnected(ServerConnectedEvent event) { bridge.onServerConnected(event); }
    @Subscribe public void onServerPreConnect(ServerPreConnectEvent event) { bridge.onServerPreConnect(event); }
    @Subscribe public void onCommandExecute(CommandExecuteEvent event) { bridge.onCommandExecute(event); }
    @Subscribe public void onPlayerChat(PlayerChatEvent event) { bridge.onPlayerChat(event); }
    @Subscribe public void onDisconnect(DisconnectEvent event) { bridge.onDisconnect(event); }
    @Subscribe public void onProxyShutdown(ProxyShutdownEvent event) { bridge.shutdown(); }
}
