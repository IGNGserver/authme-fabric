package io.github.authme.platform.paper;

import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
import io.papermc.paper.dialog.Dialog;
import io.papermc.paper.registry.data.dialog.ActionButton;
import io.papermc.paper.registry.data.dialog.DialogBase;
import io.papermc.paper.registry.data.dialog.action.DialogAction;
import io.papermc.paper.registry.data.dialog.body.DialogBody;
import io.papermc.paper.registry.data.dialog.input.DialogInput;
import io.papermc.paper.registry.data.dialog.type.DialogType;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.entity.Player;

import java.util.ArrayList;
import java.util.List;

/**
 * Paper 1.21 dialog renderer shared by the Paper and Folia entrypoints.
 *
 * <p>All actions are ordinary AuthMe commands. That keeps the dialog path subject to the same
 * permission, session-generation and input validation checks as chat/console commands.</p>
 */
public final class PaperDialogHelper {

    private static final LegacyComponentSerializer LEGACY = LegacyComponentSerializer.legacyAmpersand();

    private PaperDialogHelper() { }

    public static boolean showLogin(Player player, AuthMeConfig config, Messages messages) {
        if (!usable(player, config, messages)) return false;
        boolean showRecovery = config.dialogShowForgotPasswordButton()
            && config.emailRegistrationConfigured();
        List<DialogInput> inputs = new ArrayList<>();
        inputs.add(input("password", message(player, messages, "dialog.login.password"),
            config.maxPasswordLength()));
        if (showRecovery) {
            inputs.add(input("email", message(player, messages, "dialog.login.recovery_email",
                "dialog.login.recoveryEmail"), 320));
        }
        List<ActionButton> buttons = new ArrayList<>();
        buttons.add(button(message(player, messages, "dialog.login.button"),
            DialogAction.commandTemplate("login $(password)")));
        if (showRecovery) {
            buttons.add(button(message(player, messages, "dialog.login.recovery_button",
                "dialog.login.recoveryButton"),
                DialogAction.commandTemplate("email recover $(email)")));
        }
        return show(player, baseDialog(messages, player, "dialog.login.title", "dialog.login.body",
            inputs, buttons, config.dialogShowBody()));
    }

    public static boolean showRegister(Player player, AuthMeConfig config, Messages messages) {
        if (!usable(player, config, messages)) return false;
        List<DialogInput> inputs = new ArrayList<>();
        String command;
        if (config.registrationType() == RegistrationType.EMAIL) {
            inputs.add(input("email", message(player, messages, "dialog.register.email"), 320));
            if (config.registrationSecondArgument() != RegisterSecondaryArgument.NONE) {
                inputs.add(input("confirmEmail", message(player, messages, "dialog.register.confirm_email",
                    "dialog.register.confirmEmail"), 320));
                command = "register $(email) $(confirmEmail)";
            } else {
                command = "register $(email)";
            }
        } else {
            inputs.add(input("password", message(player, messages, "dialog.register.password"),
                config.maxPasswordLength()));
            RegisterSecondaryArgument second = config.registrationSecondArgument();
            if (second == RegisterSecondaryArgument.CONFIRMATION) {
                inputs.add(input("confirm", message(player, messages, "dialog.register.confirm_password",
                    "dialog.register.confirmPassword"), config.maxPasswordLength()));
                command = "register $(password) $(confirm)";
            } else if (second == RegisterSecondaryArgument.EMAIL_MANDATORY
                || second == RegisterSecondaryArgument.EMAIL_OPTIONAL) {
                inputs.add(input("email", message(player, messages, "dialog.register.email"), 320));
                command = "register $(password) $(email)";
            } else {
                command = "register $(password)";
            }
        }
        ActionButton register = button(message(player, messages, "dialog.register.button"),
            DialogAction.commandTemplate(command));
        return show(player, baseDialog(messages, player, "dialog.register.title", "dialog.register.body",
            inputs, List.of(register), config.dialogShowBody()));
    }

    public static boolean showTotp(Player player, AuthMeConfig config, Messages messages) {
        if (!usable(player, config, messages)) return false;
        ActionButton verify = button(message(player, messages, "dialog.two_factor.button",
                "dialog.totp.button"),
            DialogAction.commandTemplate("2fa code $(code)"));
        return show(player, baseDialog(messages, player, "dialog.two_factor.title", "dialog.two_factor.body",
            List.of(input("code", message(player, messages, "dialog.two_factor.code", "dialog.totp.code"), 16)),
            List.of(verify), config.dialogShowBody()));
    }

    /** Builds the blocking login dialog used during Paper's configuration phase. */
    public static Dialog createPreJoinLogin(AuthMeConfig config, Messages messages, String locale) {
        if (config == null || messages == null) return null;
        List<DialogInput> inputs = List.of(DialogInput.text("password",
            component(messages.getForLocale(locale, "dialog.login.password")))
            .maxLength(config.maxPasswordLength()).build());
        List<ActionButton> buttons = new ArrayList<>();
        buttons.add(button(messages.getForLocale(locale, "dialog.login.button"),
            DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_LOGIN_SUBMIT, null)));
        if (config.dialogShowForgotPasswordButton() && config.emailRegistrationConfigured()) {
            buttons.add(button(localeMessage(messages, locale, "dialog.login.recovery_button", "Forgot Password?"),
                DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_LOGIN_RECOVERY, null)));
        }
        if (config.dialogPreJoinShowCancelButton()) {
            buttons.add(button(localeMessage(messages, locale, "dialog.cancel", "Cancel"),
                DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_LOGIN_CANCEL, null)));
        }
        return preJoinDialog(messages, locale, "dialog.login.title", "dialog.login.body", inputs, buttons,
            config.dialogPreJoinAllowCloseWithEscape(), config.dialogShowBody());
    }

    /** Builds the pre-join recovery dialog; the listener returns to the normal email flow. */
    public static Dialog createPreJoinRecovery(AuthMeConfig config, Messages messages, String locale) {
        if (config == null || messages == null) return null;
        List<DialogInput> inputs = List.of(DialogInput.text("email",
            component(localeMessage(messages, locale, "dialog.recovery.email", "Recovery Email")))
            .maxLength(320).build());
        List<ActionButton> buttons = new ArrayList<>();
        buttons.add(button(localeMessage(messages, locale, "dialog.recovery.button", "Send Recovery Email"),
            DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_RECOVERY_SUBMIT, null)));
        if (config.dialogPreJoinShowCancelButton()) {
            buttons.add(button(localeMessage(messages, locale, "dialog.cancel", "Cancel"),
                DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_RECOVERY_CANCEL, null)));
        }
        return preJoinDialog(messages, locale, "dialog.recovery.title", "dialog.recovery.body", inputs, buttons,
            false, config.dialogShowBody());
    }

    /** Builds the blocking registration dialog used during Paper's configuration phase. */
    public static Dialog createPreJoinRegister(AuthMeConfig config, Messages messages, String locale) {
        if (config == null || messages == null) return null;
        List<DialogInput> inputs = new ArrayList<>();
        if (config.registrationType() == RegistrationType.EMAIL) {
            inputs.add(DialogInput.text("email", component(messages.getForLocale(locale, "dialog.register.email")))
                .maxLength(320).build());
            if (config.registrationSecondArgument() != RegisterSecondaryArgument.NONE) {
                inputs.add(DialogInput.text("confirmEmail", component(messages.getForLocale(locale,
                    "dialog.register.confirm_email"))).maxLength(320).build());
            }
        } else {
            inputs.add(DialogInput.text("password", component(messages.getForLocale(locale,
                "dialog.register.password"))).maxLength(config.maxPasswordLength()).build());
            RegisterSecondaryArgument second = config.registrationSecondArgument();
            if (second == RegisterSecondaryArgument.CONFIRMATION) {
                inputs.add(DialogInput.text("confirm", component(messages.getForLocale(locale,
                    "dialog.register.confirm_password"))).maxLength(config.maxPasswordLength()).build());
            } else if (second == RegisterSecondaryArgument.EMAIL_MANDATORY
                || second == RegisterSecondaryArgument.EMAIL_OPTIONAL) {
                inputs.add(DialogInput.text("email", component(messages.getForLocale(locale,
                    "dialog.register.email"))).maxLength(320).build());
            }
        }
        List<ActionButton> buttons = new ArrayList<>();
        buttons.add(button(messages.getForLocale(locale, "dialog.register.button"),
            DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_REGISTER_SUBMIT, null)));
        if (config.dialogPreJoinShowCancelButton()) {
            buttons.add(button(localeMessage(messages, locale, "dialog.cancel", "Cancel"),
                DialogAction.customClick(PaperDialogActionKeys.PRE_JOIN_REGISTER_CANCEL, null)));
        }
        return preJoinDialog(messages, locale, "dialog.register.title", "dialog.register.body", inputs, buttons,
            config.dialogPreJoinAllowCloseWithEscape(), config.dialogShowBody());
    }

    public static void close(Player player) {
        if (player == null) return;
        try {
            player.closeDialog();
        } catch (RuntimeException ignored) {
            // A disconnect can race dialog cleanup. There is no useful recovery action here.
        }
    }

    private static boolean show(Player player, Dialog dialog) {
        if (dialog == null || player == null || !player.isOnline()) return false;
        try {
            player.showDialog(dialog);
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static Dialog baseDialog(Messages messages, Player player, String titleKey, String bodyKey,
                                     List<DialogInput> inputs, List<ActionButton> buttons, boolean showBody) {
        DialogBase.Builder base = DialogBase.builder(component(message(player, messages, titleKey)))
            .inputs(inputs)
            .afterAction(DialogBase.DialogAfterAction.CLOSE);
        if (showBody && messages.has(bodyKey)) {
            String body = message(player, messages, bodyKey);
            if (!body.isBlank()) base.body(List.of(DialogBody.plainMessage(component(body))));
        }
        DialogBase built = base.build();
        return Dialog.create(factory -> factory.empty()
            .base(built)
            .type(DialogType.multiAction(buttons).build()));
    }

    private static Dialog preJoinDialog(Messages messages, String locale, String titleKey, String bodyKey,
                                        List<DialogInput> inputs, List<ActionButton> buttons,
                                        boolean canCloseWithEscape, boolean showBody) {
        DialogBase.Builder base = DialogBase.builder(component(messages.getForLocale(locale, titleKey)))
            .inputs(inputs)
            .canCloseWithEscape(canCloseWithEscape)
            .afterAction(DialogBase.DialogAfterAction.WAIT_FOR_RESPONSE);
        String body = messages.getForLocale(locale, bodyKey);
        if (showBody && !body.startsWith("&c[missing message:") && !body.isBlank()) {
            base.body(List.of(DialogBody.plainMessage(component(body))));
        }
        return Dialog.create(factory -> factory.empty()
            .base(base.build())
            .type(DialogType.multiAction(buttons).build()));
    }

    private static DialogInput input(String key, String label, int maxLength) {
        return DialogInput.text(key, component(label)).maxLength(Math.max(1, Math.min(512, maxLength))).build();
    }

    private static ActionButton button(String label, DialogAction action) {
        return ActionButton.builder(component(label)).action(action).build();
    }

    private static Component component(String value) {
        return LEGACY.deserialize(value == null ? "" : value);
    }

    private static String message(Player player, Messages messages, String key, String... fallbacks) {
        String locale = player == null ? "" : player.getLocale();
        String value = messages.getForLocale(locale, key);
        if (!value.startsWith("&c[missing message:")) return value;
        for (String fallback : fallbacks) {
            value = messages.getForLocale(locale, fallback);
            if (!value.startsWith("&c[missing message:")) return value;
        }
        return value;
    }

    private static String localeMessage(Messages messages, String locale, String key, String fallback) {
        String value = messages.getForLocale(locale, key);
        return value.startsWith("&c[missing message:") ? fallback : value;
    }

    private static boolean usable(Player player, AuthMeConfig config, Messages messages) {
        return player != null && player.isOnline() && config != null && config.dialogPostJoinEnabled()
            && messages != null;
    }
}
