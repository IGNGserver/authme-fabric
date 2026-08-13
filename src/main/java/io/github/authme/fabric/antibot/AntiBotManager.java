package io.github.authme.fabric.antibot;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.util.Log;

import java.util.Deque;
import java.util.LinkedList;
import java.util.Locale;

/**
 * Lightweight anti-bot / anti-spam protector. Tracks the rate of recent connections, and if it
 * exceeds the configured threshold within the configured interval, rejects new connections for a
 * short safety window. This mirrors the spirit of AuthMe's AntiBot (ConfigurableBasicCaptchaShield).
 */
public final class AntiBotManager {

    private final boolean enabled;
    private final int intervalSeconds;
    private final int thresholdConnections;

    private final Deque<Long> recentJoinTimes = new LinkedList<>();
    private long safetyBlockUntil;
    private int blockedSince;

    public AntiBotManager(AuthMeConfig config) {
        this.enabled = config.antiBotEnabled();
        this.intervalSeconds = Math.max(1, config.antiBotInterval());
        this.thresholdConnections = Math.max(1, config.antiBotThreshold());
    }

    public synchronized void notifyJoin(String ip) {
        if (!enabled) return;
        long now = System.currentTimeMillis();
        prune(now);
        recentJoinTimes.addLast(now);
        if (recentJoinTimes.size() >= thresholdConnections) {
            long blockMs = (intervalSeconds * 3L) * 1000L;
            safetyBlockUntil = Math.max(safetyBlockUntil, now + blockMs);
            blockedSince++;
            Log.warn("AntiBot: connection threshold reached (" + thresholdConnections
                + " in " + intervalSeconds + "s). New joins are temporarily blocked for "
                + (blockMs / 1000) + "s. (ip=" + anonymizeIp(ip) + ")");
        }
    }

    /**
     * @return true if new connections should be rejected right now due to the safety window.
     */
    public synchronized boolean shouldBlockNewJoins() {
        if (!enabled) return false;
        long now = System.currentTimeMillis();
        if (now >= safetyBlockUntil) {
            return false;
        }
        return true;
    }

    public synchronized int remainingBlockSeconds() {
        if (safetyBlockUntil <= System.currentTimeMillis()) return 0;
        return (int) Math.ceil((safetyBlockUntil - System.currentTimeMillis()) / 1000.0);
    }

    private void prune(long now) {
        long cutoff = now - intervalSeconds * 1000L;
        while (!recentJoinTimes.isEmpty() && recentJoinTimes.peekFirst() < cutoff) {
            recentJoinTimes.pollFirst();
        }
    }

    private static String anonymizeIp(String ip) {
        if (ip == null || ip.isEmpty()) return "?";
        String[] parts = ip.split("\\.");
        if (parts.length == 4) {
            return parts[0] + "." + parts[1] + ".x.x";
        }
        return ip.toLowerCase(Locale.ROOT);
    }
}