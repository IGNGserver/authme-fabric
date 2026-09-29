package io.github.authme.platform.paper;

import org.bukkit.entity.Player;

/** Scheduler boundary shared by Paper and Folia adapters. */
public interface PlatformScheduler {

    void runAsync(Runnable task);

    /**
     * Schedules work on the player's owning thread.
     *
     * @return false when the entity has already retired and the task cannot run
     */
    boolean runForPlayer(Player player, Runnable task);

    void runGlobal(Runnable task);

    void runDelayedForPlayer(Player player, Runnable task, long delayTicks);

    void runDelayedGlobal(Runnable task, long delayTicks);
}
