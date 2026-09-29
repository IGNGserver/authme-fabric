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

    private volatile boolean enabled;
    private final int intervalSeconds;
    private final int thresholdConnections;
    private final int durationMinutes;
    private final int activationDelaySeconds;

    private final Deque<Long> recentJoinTimes = new LinkedList<>();
    private long safetyBlockUntil;
    private long safetyBlockFrom;
    private int blockedSince;
    private boolean deactivationNoticePending;

    public AntiBotManager(AuthMeConfig config) {
        this.enabled = config.antiBotEnabled();
        this.intervalSeconds = Math.max(1, config.antiBotInterval());
        this.thresholdConnections = Math.max(1, config.antiBotThreshold());
        this.durationMinutes = Math.max(1, config.antiBotDurationMinutes());
        this.activationDelaySeconds = Math.max(0, config.antiBotDelaySeconds());
    }

    public synchronized boolean notifyJoin(String ip) {
        if (!enabled) return false;
        long now = System.currentTimeMillis();
        prune(now);
        recentJoinTimes.addLast(now);
        if (recentJoinTimes.size() >= thresholdConnections) {
            long blockMs = durationMinutes * 60_000L;
            long from = now + activationDelaySeconds * 1000L;
            boolean alreadyScheduled = safetyBlockUntil > now;
            safetyBlockFrom = Math.max(safetyBlockFrom, from);
            safetyBlockUntil = Math.max(safetyBlockUntil, from + blockMs);
            blockedSince++;
            Log.warn("AntiBot: connection threshold reached (" + thresholdConnections
                + " in " + intervalSeconds + "s). New joins will be temporarily blocked for "
                + (blockMs / 1000) + "s after a " + activationDelaySeconds + "s delay. (ip=" + anonymizeIp(ip) + ")");
            return !alreadyScheduled;
        }
        return false;
    }

    /**
     * @return true if new connections should be rejected right now due to the safety window.
     */
    public synchronized boolean shouldBlockNewJoins() {
        if (!enabled) return false;
        long now = System.currentTimeMillis();
        if (safetyBlockUntil > 0L && now >= safetyBlockUntil) {
            safetyBlockFrom = 0L;
            safetyBlockUntil = 0L;
            recentJoinTimes.clear();
            deactivationNoticePending = true;
            return false;
        }
        if (now < safetyBlockFrom || safetyBlockUntil <= 0L) {
            return false;
        }
        return true;
    }

    /** Returns and clears the one-shot notification emitted after an automatic safety window ends. */
    public synchronized boolean consumeDeactivationNotice() {
        boolean pending = deactivationNoticePending;
        deactivationNoticePending = false;
        return pending;
    }

    public synchronized int remainingBlockSeconds() {
        if (safetyBlockUntil <= System.currentTimeMillis()) return 0;
        return (int) Math.ceil((safetyBlockUntil - System.currentTimeMillis()) / 1000.0);
    }

    public synchronized boolean isEnabled() {
        return enabled;
    }

    public synchronized boolean setEnabled(boolean enabled) {
        boolean changed = this.enabled != enabled;
        this.enabled = enabled;
        if (!enabled) {
            safetyBlockUntil = 0L;
            safetyBlockFrom = 0L;
            deactivationNoticePending = false;
            recentJoinTimes.clear();
        }
        return changed;
    }

    public synchronized boolean toggle() {
        setEnabled(!enabled);
        return enabled;
    }

    public synchronized void reset() {
        recentJoinTimes.clear();
        safetyBlockUntil = 0L;
        safetyBlockFrom = 0L;
        deactivationNoticePending = false;
        blockedSince = 0;
    }

    public synchronized int blockedSince() {
        return blockedSince;
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
