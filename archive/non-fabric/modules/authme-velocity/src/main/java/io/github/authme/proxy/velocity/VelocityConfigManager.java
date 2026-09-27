package io.github.authme.proxy.velocity;

import io.github.authme.proxy.core.ProxyConfig;

import java.io.IOException;
import java.nio.file.Path;

final class VelocityConfigManager {

    private final Path dataDirectory;

    VelocityConfigManager(Path dataDirectory) {
        this.dataDirectory = dataDirectory;
    }

    ProxyConfig load() throws IOException {
        return ProxyConfig.load(dataDirectory);
    }
}
