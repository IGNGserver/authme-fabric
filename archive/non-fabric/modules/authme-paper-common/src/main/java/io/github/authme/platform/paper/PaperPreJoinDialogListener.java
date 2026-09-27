package io.github.authme.platform.paper;

import com.destroystokyo.paper.event.player.PlayerConnectionCloseEvent;
import com.destroystokyo.paper.profile.PlayerProfile;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
import io.github.authme.fabric.datasource.DataSource;
import io.papermc.paper.connection.PlayerConfigurationConnection;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.dialog.DialogResponseView;
import io.papermc.paper.event.connection.configuration.AsyncPlayerConnectionConfigureEvent;
import io.papermc.paper.event.player.PlayerCustomClickEvent;
import org.bukkit.Bukkit;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;

import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

/**
 * Paper/Folia 1.21 configuration-phase authentication dialogs.
 *
 * <p>The connection is held only while a bounded dialog future is pending. Submitted values are
 * copied into the runtime's one-connection handoff and are consumed exactly once by onJoin; all
 * actual password, registration and recovery decisions still run through PlatformAuthService.</p>
 */
public final class PaperPreJoinDialogListener implements Listener, AutoCloseable {

    private static final int DIALOG_MIN_PROTOCOL = 771;
    private static final int MAX_PENDING_DIALOGS = 1_024;

    private final PaperAuthRuntime runtime;
    private final ConcurrentMap<UUID, PendingDialog> pending = new ConcurrentHashMap<>();

    public PaperPreJoinDialogListener(PaperAuthRuntime runtime) {
        this.runtime = runtime;
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onPlayerConfigure(AsyncPlayerConnectionConfigureEvent event) {
        AuthMeConfig config = runtime.config();
        if (!config.dialogPreJoinEnabled()) return;

        PlayerConfigurationConnection connection = event.getConnection();
        PlayerProfile profile = connection.getProfile();
        UUID playerId = profile == null ? null : profile.getId();
        String playerName = profile == null ? null : profile.getName();
        if (playerId == null || playerName == null || playerName.isBlank()) return;

        PendingDialog previous = pending.remove(playerId);
        if (previous != null) previous.response.complete(PreJoinResult.kick(timeoutMessage()));
        runtime.clearPreJoin(playerId);

        if (runtime.preJoinShouldSkip() || runtime.preJoinUnrestricted(playerName)
            || !clientCanUseDialogs(playerId)) return;

        synchronized (pending) {
            if (pending.size() >= MAX_PENDING_DIALOGS && !pending.containsKey(playerId)) return;
        }
        DataSource.LookupResult lookup = runtime.preJoinLookup(playerName);
        if (!lookup.successful()) return;
        boolean registration = lookup.auth() == null;
        if (registration) {
            if (!config.registrationForce() || config.kickNonRegistered()) return;
        } else if (runtime.preJoinPremiumMatches(lookup.auth(), playerId)) {
            return;
        }

        Messages messages = runtime.dialogMessages();
        if (messages == null) return;
        PendingDialog current = new PendingDialog(playerId, registration,
            new CompletableFuture<>());
        current.response.completeOnTimeout(PreJoinResult.kick(timeoutMessage()),
            config.dialogPreJoinTimeoutSeconds(), TimeUnit.SECONDS);
        synchronized (pending) {
            if (pending.size() >= MAX_PENDING_DIALOGS && !pending.containsKey(playerId)) {
                // Do not create an unbounded number of configuration-phase waits. The normal
                // post-join flow still enforces authentication for this connection.
                return;
            }
            if (pending.putIfAbsent(playerId, current) != null) return;
        }

        Dialog dialog = registration
            ? PaperDialogHelper.createPreJoinRegister(config, messages, "")
            : PaperDialogHelper.createPreJoinLogin(config, messages, "");
        if (dialog == null) {
            pending.remove(playerId, current);
            return;
        }
        try {
            connection.getAudience().showDialog(dialog);
        } catch (RuntimeException exception) {
            pending.remove(playerId, current);
            return;
        }

        PreJoinResult result;
        try {
            result = current.response.join();
        } finally {
            pending.remove(playerId, current);
        }
        apply(playerId, result);
        try {
            connection.getAudience().closeDialog();
        } catch (RuntimeException ignored) {
            // The client may have disconnected while the configuration future was completing.
        }
    }

    @EventHandler(priority = EventPriority.NORMAL)
    public void onPlayerCustomClick(PlayerCustomClickEvent event) {
        if (!(event.getCommonConnection() instanceof PlayerConfigurationConnection connection)) return;
        PlayerProfile profile = connection.getProfile();
        UUID playerId = profile == null ? null : profile.getId();
        if (playerId == null) return;
        PendingDialog current = pending.get(playerId);
        if (current == null) return;

        if (PaperDialogActionKeys.PRE_JOIN_LOGIN_RECOVERY.equals(event.getIdentifier())
            && !current.registration) {
            Dialog recovery = PaperDialogHelper.createPreJoinRecovery(runtime.config(),
                runtime.dialogMessages(), "");
            if (recovery != null) {
                try {
                    connection.getAudience().showDialog(recovery);
                } catch (RuntimeException ignored) {
                    // The original future remains bounded and will fail closed on timeout.
                }
            }
            return;
        }

        DialogResponseView view = event.getDialogResponseView();
        if (PaperDialogActionKeys.PRE_JOIN_LOGIN_SUBMIT.equals(event.getIdentifier())
            && !current.registration) {
            String password = text(view, "password");
            if (password == null || password.isBlank() || password.length() > 512) {
                current.response.complete(PreJoinResult.kick(message("dialog.invalidPassword",
                    "Invalid password input.")));
            } else {
                current.response.complete(PreJoinResult.login(password));
            }
            return;
        }

        if (PaperDialogActionKeys.PRE_JOIN_RECOVERY_SUBMIT.equals(event.getIdentifier())
            && !current.registration) {
            String email = text(view, "email");
            if (email == null || email.isBlank() || email.length() > 320) {
                current.response.complete(PreJoinResult.kick(message("dialog.invalidEmail",
                    "Invalid email address.")));
            } else {
                current.response.complete(PreJoinResult.recovery(email));
            }
            return;
        }

        if (PaperDialogActionKeys.PRE_JOIN_LOGIN_CANCEL.equals(event.getIdentifier())
            || PaperDialogActionKeys.PRE_JOIN_RECOVERY_CANCEL.equals(event.getIdentifier())) {
            current.response.complete(runtime.config().dialogPreJoinLoginCancelKicks()
                ? PreJoinResult.kick(message("dialog.login.canceled", "Login canceled."))
                : PreJoinResult.none());
            return;
        }

        if (PaperDialogActionKeys.PRE_JOIN_REGISTER_SUBMIT.equals(event.getIdentifier())
            && current.registration) {
            String first;
            String second = "";
            if (runtime.config().registrationType() == RegistrationType.EMAIL) {
                first = text(view, "email");
                if (runtime.config().registrationSecondArgument() != RegisterSecondaryArgument.NONE) {
                    second = text(view, "confirmEmail");
                }
            } else {
                first = text(view, "password");
                RegisterSecondaryArgument mode = runtime.config().registrationSecondArgument();
                if (mode == RegisterSecondaryArgument.CONFIRMATION) second = text(view, "confirm");
                else if (mode == RegisterSecondaryArgument.EMAIL_MANDATORY
                    || mode == RegisterSecondaryArgument.EMAIL_OPTIONAL) second = text(view, "email");
                if (mode == RegisterSecondaryArgument.EMAIL_OPTIONAL && second == null) second = "";
            }
            if (first == null || first.length() > 512 || second == null || second.length() > 512) {
                current.response.complete(PreJoinResult.kick(message("dialog.invalidPassword",
                    "Invalid registration input.")));
            } else {
                current.response.complete(PreJoinResult.register(first, second));
            }
            return;
        }

        if (PaperDialogActionKeys.PRE_JOIN_REGISTER_CANCEL.equals(event.getIdentifier())
            && current.registration) {
            current.response.complete(runtime.config().dialogPreJoinRegisterCancelKicks()
                ? PreJoinResult.kick(message("dialog.register.canceled", "Registration canceled."))
                : PreJoinResult.none());
        }
    }

    @EventHandler(priority = EventPriority.MONITOR)
    public void onPlayerConnectionClose(PlayerConnectionCloseEvent event) {
        PendingDialog current = pending.remove(event.getPlayerUniqueId());
        if (current != null) current.response.complete(PreJoinResult.none());
        runtime.clearPreJoin(event.getPlayerUniqueId());
    }

    @Override
    public void close() {
        for (PendingDialog current : pending.values()) {
            current.response.complete(PreJoinResult.kick(timeoutMessage()));
        }
        pending.clear();
    }

    private void apply(UUID playerId, PreJoinResult result) {
        if (result == null || result.kind == PreJoinKind.NONE) return;
        switch (result.kind) {
            case LOGIN -> runtime.storePreJoinLogin(playerId, result.first);
            case REGISTER -> runtime.storePreJoinRegistration(playerId, result.first, result.second);
            case RECOVERY -> runtime.storePreJoinRecovery(playerId, result.first);
            case KICK -> runtime.storePreJoinKick(playerId, result.first);
            case NONE -> { }
        }
    }

    private String timeoutMessage() {
        return message("dialog.timeout", "Authentication dialog timed out.");
    }

    private String message(String key, String fallback) {
        Messages messages = runtime.dialogMessages();
        if (messages == null) return fallback;
        String value = messages.getForLocale("", key);
        return value.startsWith("&c[missing message:") ? fallback : value;
    }

    private static String text(DialogResponseView view, String key) {
        if (view == null) return null;
        try {
            return view.getText(key);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    /** ViaVersion is optional; when present, avoid sending dialog packets to pre-1.21.6 clients. */
    private static boolean clientCanUseDialogs(UUID playerId) {
        try {
            if (Bukkit.getPluginManager().getPlugin("ViaVersion") == null) return true;
            Class<?> viaApi = Class.forName("com.viaversion.viaversion.api.ViaAPI");
            Class<?> via = Class.forName("com.viaversion.viaversion.api.Via");
            Object api = via.getMethod("getAPI").invoke(null);
            Object version = viaApi.getMethod("getPlayerVersion", UUID.class).invoke(api, playerId);
            return version instanceof Number number && number.intValue() >= DIALOG_MIN_PROTOCOL;
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            return true;
        }
    }

    private static final class PendingDialog {
        private final UUID playerId;
        private final boolean registration;
        private final CompletableFuture<PreJoinResult> response;

        private PendingDialog(UUID playerId, boolean registration,
                              CompletableFuture<PreJoinResult> response) {
            this.playerId = playerId;
            this.registration = registration;
            this.response = response;
        }
    }

    private enum PreJoinKind { LOGIN, REGISTER, RECOVERY, KICK, NONE }

    private static final class PreJoinResult {
        private final PreJoinKind kind;
        private final String first;
        private final String second;

        private PreJoinResult(PreJoinKind kind, String first, String second) {
            this.kind = kind;
            this.first = first;
            this.second = second;
        }

        private static PreJoinResult login(String password) {
            return new PreJoinResult(PreJoinKind.LOGIN, password, "");
        }

        private static PreJoinResult register(String first, String second) {
            return new PreJoinResult(PreJoinKind.REGISTER, first, second);
        }

        private static PreJoinResult recovery(String email) {
            return new PreJoinResult(PreJoinKind.RECOVERY, email, "");
        }

        private static PreJoinResult kick(String message) {
            return new PreJoinResult(PreJoinKind.KICK, message, "");
        }

        private static PreJoinResult none() {
            return new PreJoinResult(PreJoinKind.NONE, "", "");
        }
    }
}
