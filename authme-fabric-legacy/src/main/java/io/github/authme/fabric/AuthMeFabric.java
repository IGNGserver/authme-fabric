package io.github.authme.fabric;

import io.github.authme.fabric.command.AuthMeCommands;
import io.github.authme.fabric.events.AuthMeEvents;
import io.github.authme.fabric.network.ProxyBridge;
import io.github.authme.fabric.util.Log;
import io.github.authme.fabric.util.Log4jLogSink;

import net.fabricmc.api.ModInitializer;
import net.fabricmc.fabric.api.command.v2.CommandRegistrationCallback;
import net.fabricmc.fabric.api.event.lifecycle.v1.ServerLifecycleEvents;
import net.fabricmc.loader.api.FabricLoader;

/**
 * AuthMe Reloaded → Fabric port. Entry point: registers commands and events during mod load, and
 * boots the central {@link AuthMe} service once the logical server has started (after the database
 * and config have a directory to live in).
 */
public final class AuthMeFabric implements ModInitializer {

    /** Returns the version declared by this build's fabric.mod.json. */
    public static String version() {
        return FabricLoader.getInstance()
            .getModContainer("authme")
            .map(mod -> mod.getMetadata().getVersion().getFriendlyString())
            .orElse("unknown");
    }

    @Override
    public void onInitialize() {
        Log.setSink(new Log4jLogSink());
        AuthMe.require(); // create the singleton holder early

        CommandRegistrationCallback.EVENT.register((dispatcher, context, selection) -> AuthMeCommands.register(dispatcher));
        ProxyBridge.register();
        AuthMeEvents.register();

        ServerLifecycleEvents.SERVER_STARTED.register(server -> {
            AuthMe am = AuthMe.require();
            boolean ok = am.init(server);
            if (!ok) {
                Log.error("AuthMe failed to initialise; stopping the server to keep authentication fail-closed.");
                server.halt(false);
                return;
            }
            ProxyBridge.bind(am, server);
            Log.info("AuthMe Fabric is now protecting this server.");
        });

        ServerLifecycleEvents.SERVER_STOPPING.register(server -> {
            AuthMe am = AuthMe.get();
            if (am != null) am.shutdown();
        });

        Log.info("AuthMe Fabric v" + version() + " (legacy) loaded — MC 1.19.4–1.20.4 (GPL-3.0).");
    }
}
