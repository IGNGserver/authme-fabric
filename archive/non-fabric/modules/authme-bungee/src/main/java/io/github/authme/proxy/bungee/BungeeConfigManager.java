package io.github.authme.proxy.bungee;

import io.github.authme.proxy.core.ProxyConfig;

import java.io.IOException;
import java.nio.file.Path;

final class BungeeConfigManager {

    private final Path dataDirectory;

    BungeeConfigManager(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
    }

    ProxyConfig load() throws IOException {
        return ProxyConfig.load(dataDirectory);
    }
}
