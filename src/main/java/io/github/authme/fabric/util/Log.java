package io.github.authme.fabric.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Thin wrapper over the server's log4j2 logger.
 */
public final class Log {

    private static final Logger LOGGER = LogManager.getLogger("AuthMe-Fabric");

    private Log() {
    }

    public static void info(String message) {
        LOGGER.info("[AuthMe] {}", message);
    }

    public static void warn(String message) {
        LOGGER.warn("[AuthMe] {}", message);
    }

    public static void warn(String message, Throwable t) {
        LOGGER.warn("[AuthMe] {}", message, t);
    }

    public static void error(String message) {
        LOGGER.error("[AuthMe] {}", message);
    }

    public static void error(String message, Throwable t) {
        LOGGER.error("[AuthMe] {}", message, t);
    }
}