package io.github.authme.fabric.util;

/**
 * Thin logging facade. Pure Java — does not pull in log4j (which is provided by the Minecraft
 * server). Each platform module installs a {@link Sink} that delegates to the platform logger
 * at startup; until then the default {@link Sink} writes to {@link System#err}.
 */
public final class Log {

    private Log() {
    }

    /** Pluggable sink so the core can log without depending on any platform's logger. */
    public interface Sink {
        void info(String message);
        void warn(String message);
        void warn(String message, Throwable t);
        void error(String message);
        void error(String message, Throwable t);
    }

    private static volatile Sink sink = new DefaultSink();

    public static void setSink(Sink sink) {
        Log.sink = sink == null ? new DefaultSink() : sink;
    }

    public static void info(String message) {
        sink.info(message);
    }

    public static void warn(String message) {
        sink.warn(message);
    }

    public static void warn(String message, Throwable t) {
        sink.warn(message, t);
    }

    public static void error(String message) {
        sink.error(message);
    }

    public static void error(String message, Throwable t) {
        sink.error(message, t);
    }

    private static final class DefaultSink implements Sink {
        @Override public void info(String m) { System.out.println("[AuthMe INFO] " + m); }
        @Override public void warn(String m) { System.err.println("[AuthMe WARN] " + m); }
        @Override public void warn(String m, Throwable t) { System.err.println("[AuthMe WARN] " + m); t.printStackTrace(System.err); }
        @Override public void error(String m) { System.err.println("[AuthMe ERROR] " + m); }
        @Override public void error(String m, Throwable t) { System.err.println("[AuthMe ERROR] " + m); t.printStackTrace(System.err); }
    }
}