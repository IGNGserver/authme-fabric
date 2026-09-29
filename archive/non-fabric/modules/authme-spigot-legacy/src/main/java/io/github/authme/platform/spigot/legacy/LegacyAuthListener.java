package io.github.authme.platform.spigot.legacy;

import org.bukkit.entity.Player;
import org.bukkit.entity.Projectile;
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
import org.bukkit.event.player.AsyncPlayerChatEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerPickupItemEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerTeleportEvent;
import org.bukkit.event.server.TabCompleteEvent;

final class LegacyAuthListener implements Listener {

    private final LegacyAuthRuntime runtime;

    LegacyAuthListener(LegacyAuthRuntime runtime) { this.runtime = runtime; }

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
        runtime.join(player);
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
        boolean blocked = runtime.blocked(player);
        runtime.quit(player);
        if (runtime.config().removeLeaveMessage()
            || (blocked && runtime.config().removeUnloggedLeaveMessage())) event.setQuitMessage(null);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onChat(AsyncPlayerChatEvent event) {
        if (!runtime.mayChat(event.getPlayer())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("Please log in before chatting.");
            return;
        }
        if (runtime.config().hideChat()) event.getRecipients().removeIf(runtime::hideChatFrom);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onCommand(PlayerCommandPreprocessEvent event) {
        if (runtime.blocked(event.getPlayer()) && !runtime.allowedCommand(event.getPlayer(), event.getMessage())) {
            event.setCancelled(true);
            event.getPlayer().sendMessage("Please log in before using commands.");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onTabComplete(TabCompleteEvent event) {
        if (event.getSender() instanceof Player player && runtime.blocked(player)
            && runtime.config().denyTabCompleteBeforeLogin()) {
            event.setCompletions(java.util.List.of());
            event.setCancelled(true);
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
        if (runtime.blocked(event.getPlayer()) && runtime.config().noTeleport()) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onBreak(BlockBreakEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlace(BlockPlaceEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInteract(PlayerInteractEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onInteractEntity(PlayerInteractEntityEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onConsume(org.bukkit.event.player.PlayerItemConsumeEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onSwapHands(org.bukkit.event.player.PlayerSwapHandItemsEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onFish(org.bukkit.event.player.PlayerFishEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onBed(org.bukkit.event.player.PlayerBedEnterEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onArmorStand(org.bukkit.event.player.PlayerArmorStandManipulateEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player && runtime.blocked(player)) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDamageByEntity(EntityDamageByEntityEvent event) {
        if (isBlockedDamager(event.getDamager())) {
            event.setCancelled(true);
        } else if (event.getEntity() instanceof Player player && runtime.blocked(player)) {
            event.setCancelled(true);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onProjectileLaunch(ProjectileLaunchEvent event) {
        if (event.getEntity().getShooter() instanceof Player player && runtime.blocked(player)) {
            event.setCancelled(true);
        }
    }

    private boolean isBlockedDamager(org.bukkit.entity.Entity damager) {
        if (damager instanceof Player player) return runtime.blocked(player);
        if (damager instanceof Projectile projectile
            && projectile.getShooter() instanceof Player player) {
            return runtime.blocked(player);
        }
        return false;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onOpen(InventoryOpenEvent event) {
        if (event.getPlayer() instanceof Player player && runtime.blocked(player)
            && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onClick(InventoryClickEvent event) {
        if (event.getWhoClicked() instanceof Player player && runtime.blocked(player)
            && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDrag(InventoryDragEvent event) {
        if (event.getWhoClicked() instanceof Player player && runtime.blocked(player)
            && !runtime.isUnrestrictedInventory(player, event.getView().getTitle())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDrop(PlayerDropItemEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPickup(PlayerPickupItemEvent event) {
        if (runtime.blocked(event.getPlayer())) event.setCancelled(true);
    }

    /** Covers the modern event path while retaining PlayerPickupItemEvent for older Spigot APIs. */
    @EventHandler(priority = EventPriority.HIGHEST)
    public void onEntityPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && runtime.blocked(player)) event.setCancelled(true);
    }
}
