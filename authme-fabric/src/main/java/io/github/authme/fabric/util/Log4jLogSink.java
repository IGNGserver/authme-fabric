package io.github.authme.fabric.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * log4j2-backed {@link io.github.authme.fabric.util.Log.Sink} for the modern Fabric module.
 * Installed by the server entrypoint at bootstrap so the shared core uses the server logger.
 */
public final class Log4jLogSink implements Log.Sink {

    private static final Logger LOGGER = LogManager.getLogger("AuthMe-Fabric");

    @Override public void info(String m) { LOGGER.info("[AuthMe] {}", m); }
    @Override public void warn(String m) { LOGGER.warn("[AuthMe] {}", m); }
    @Override public void warn(String m, Throwable t) { LOGGER.warn("[AuthMe] {}", m, t); }
    @Override public void error(String m) { LOGGER.error("[AuthMe] {}", m); }
    @Override public void error(String m, Throwable t) { LOGGER.error("[AuthMe] {}", m, t); }
}