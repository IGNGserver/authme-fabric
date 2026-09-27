package io.github.authme.platform.paper;

import io.papermc.paper.event.player.AsyncChatEvent;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityDamageByEntityEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.entity.ProjectileLaunchEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryDragEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPickupItemEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.event.server.TabCompleteEvent;
import org.bukkit.entity.Projectile;
import org.bukkit.entity.Player;
import org.bukkit.event.player.PlayerItemConsumeEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import org.bukkit.event.player.PlayerFishEvent;
import org.bukkit.event.player.PlayerBedEnterEvent;
import org.bukkit.event.player.PlayerArmorStandManipulateEvent;

/** Fail-closed Paper/Folia event boundary for unauthenticated players. */
public final class PaperAuthListener implements Listener {

    private final PaperAuthRuntime runtime;

    public PaperAuthListener(PaperAuthRuntime runtime) {
        this.runtime = runtime;
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        if (runtime.config().removeJoinMessage() || runtime.config().delayJoinMessage()) event.setJoinMessage(null);
        else if (!runtime.config().customJoinMessage().isBlank()) {
            String message = runtime.config().customJoinMessage()
                .replace("{PLAYER}", player.getName())
                .replace("{DISPLAYNAME}", player.getDisplayName())
                .replace("{DISPLAYNAMENOCOLOR}", org.bukkit.ChatColor.stripColor(player.getDisplayName()));
            event.setJoinMessage(org.bukkit.ChatColor.translateAlternateColorCodes('&', message));
        }
        runtime.onJoin(player);
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent event) {
        if (!runtime.databaseAvailableForJoin(event.getName())) {
            event.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER,
                "Authentication database unavailable.");
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        boolean blocked = runtime.isBlocked(player);
        runtime.onQuit(player);
        if (runtime.config().removeLeaveMessage()
            || (blocked && runtime.config().removeUnloggedLeaveMessage())) event.setQuitMessage(null);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (runtime.isBlocked(event.getPlayer()) && !runtime.isAllowedCommand(event.getPlayer(), event.getMessage())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("Please log in before using commands.");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onTabComplete(TabCompleteEvent event) {
        if (event.getSender() instanceof Player player && runtime.isBlocked(player)
            && runtime.config().denyTabCompleteBeforeLogin()) {
            event.setCompletions(java.util.List.of());
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onChat(AsyncChatEvent event) {
        if (!runtime.mayChat(event.getPlayer())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("Please log in before chatting.");
            return;
        }
        if (runtime.config().hideChat()) {
            event.viewers().removeIf(viewer -> viewer instanceof Player player && runtime.hideChatFrom(player));
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onMove(PlayerMoveEvent event) {
        if (event.getTo() != null && !runtime.mayMove(event.getPlayer(), event.getFrom(), event.getTo())) {
            event.setTo(event.getFrom());
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onTeleport(PlayerTeleportEvent event) {
        if (runtime.isBlocked(event.getPlayer()) && runtime.config().noTeleport()) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onBlockBreak(BlockBreakEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onBlockPlace(BlockPlaceEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInteract(PlayerInteractEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onConsume(PlayerItemConsumeEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onSwapHands(PlayerSwapHandItemsEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onFish(PlayerFishEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onBed(PlayerBedEnterEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onArmorStand(PlayerArmorStandManipulateEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof org.bukkit.entity.Player player) {
            if (runtime.isBlocked(player)) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        if (isBlockedDamager(event.getDamager())) {
            event.setCancelled(true);
        } else if (event.getEntity() instanceof org.bukkit.entity.Player player && runtime.isBlocked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onProjectileLaunch(ProjectileLaunchEvent event) {
        if (event.getEntity().getShooter() instanceof org.bukkit.entity.Player player
            && runtime.isBlocked(player)) {
            event.setCancelled(true);
        }
    }

    private boolean isBlockedDamager(org.bukkit.entity.Entity damager) {
        if (damager instanceof org.bukkit.entity.Player player) {
            return runtime.isBlocked(player);
        }
        if (damager instanceof Projectile projectile
            && projectile.getShooter() instanceof org.bukkit.entity.Player player) {
            return runtime.isBlocked(player);
        }
        return false;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInventoryOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof org.bukkit.entity.Player player) {
            if (runtime.isBlocked(player)
                && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInventoryClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof org.bukkit.entity.Player player) {
            if (runtime.isBlocked(player)
                && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInventoryDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof org.bukkit.entity.Player player) {
            if (runtime.isBlocked(player)
                && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDrop(PlayerDropItemEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPickup(PlayerPickupItemEvent event) {
        if (runtime.isBlocked(event.getPlayer())) event.setCancelled(true);
    }

    /** Modern Bukkit emits this event for item pickups; keep the legacy event as a compatibility path. */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onEntityPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && runtime.isBlocked(player)) event.setCancelled(true);
    }
}
