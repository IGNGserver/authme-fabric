package io.github.authme.fabric.network;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.mojang.serialization.JsonOps;
import io.github.authme.fabric.AuthMe;
import io.github.authme.fabric.config.AuthMeConfig;
import io.github.authme.fabric.config.Messages;
import io.github.authme.fabric.config.RegisterSecondaryArgument;
import io.github.authme.fabric.config.RegistrationType;
import io.github.authme.fabric.util.Log;
import net.minecraft.core.Holder;
import net.minecraft.network.protocol.common.ClientboundClearDialogPacket;
import net.minecraft.network.protocol.common.ClientboundShowDialogPacket;
import net.minecraft.server.dialog.Dialog;
import net.minecraft.server.level.ServerPlayer;

/**
 * Native Minecraft 1.21.11 dialog support. The dialog payload is decoded through the same vanilla
 * codec used for datapack dialogs, which keeps the wire format versioned by Minecraft instead of
 * introducing a private client mod or a hand-written packet codec.
 */
public final class DialogBridge {

    private DialogBridge() { }

    public static boolean showLogin(ServerPlayer player, AuthMeConfig config, Messages messages) {
        if (!enabled(player, config)) return false;
        JsonArray inputs = new JsonArray();
        inputs.add(textInput("password", message(player, messages, "dialog.login.password", "dialog.login.password"),
            config.maxPasswordLength()));
        boolean recovery = config.dialogShowForgotPasswordButton();
        if (recovery) {
            inputs.add(textInput("email", message(player, messages, "dialog.login.recovery_email", "dialog.login.recoveryEmail"), 320));
        }
        JsonArray actions = new JsonArray();
        actions.add(action(message(player, messages, "dialog.login.button", "dialog.login.button"),
            "login $(password)"));
        if (recovery) {
            actions.add(action(message(player, messages, "dialog.login.recovery_button", "dialog.login.recoveryButton"),
                "email recover $(email)"));
        }
        return show(player, dialog("multi_action",
            message(player, messages, "dialog.login.title", "dialog.login.title"),
            config.dialogShowBody() ? message(player, messages, "dialog.login.body", "dialog.login.body") : null,
            inputs, actions));
    }

    public static boolean showRegister(ServerPlayer player, AuthMeConfig config, Messages messages) {
        if (!enabled(player, config)) return false;
        JsonArray inputs = new JsonArray();
        String firstKey;
        String secondKey;
        String command;
        if (config.registrationType() == RegistrationType.EMAIL) {
            firstKey = "email";
            inputs.add(textInput(firstKey, message(player, messages, "dialog.register.email", "dialog.register.email"), 320));
            if (config.registrationSecondArgument() != RegisterSecondaryArgument.NONE) {
                secondKey = "confirmEmail";
                inputs.add(textInput(secondKey,
                    message(player, messages, "dialog.register.confirmEmail", "dialog.register.confirm_email"), 320));
                command = "register $(email) $(confirmEmail)";
            } else {
                command = "register $(email)";
            }
        } else {
            firstKey = "password";
            inputs.add(textInput(firstKey, message(player, messages, "dialog.register.password", "dialog.register.password"),
                config.maxPasswordLength()));
            RegisterSecondaryArgument secondArg = config.registrationSecondArgument();
            if (secondArg == RegisterSecondaryArgument.CONFIRMATION) {
                secondKey = "confirm";
                inputs.add(textInput(secondKey,
                    message(player, messages, "dialog.register.confirm_password", "dialog.register.confirmPassword"),
                    config.maxPasswordLength()));
                command = "register $(password) $(confirm)";
            } else if (secondArg == RegisterSecondaryArgument.EMAIL_MANDATORY
                || secondArg == RegisterSecondaryArgument.EMAIL_OPTIONAL) {
                secondKey = "email";
                inputs.add(textInput(secondKey,
                    message(player, messages, "dialog.register.email", "dialog.register.email"), 320));
                command = "register $(password) $(email)";
            } else {
                command = "register $(password)";
            }
        }
        JsonArray actions = new JsonArray();
        actions.add(action(message(player, messages, "dialog.register.button", "dialog.register.button"),
            command));
        return show(player, dialog("multi_action",
            message(player, messages, "dialog.register.title", "dialog.register.title"),
            config.dialogShowBody() ? message(player, messages, "dialog.register.body", "dialog.register.body") : null,
            inputs, actions));
    }

    public static boolean showTotp(ServerPlayer player, AuthMeConfig config, Messages messages) {
        if (!enabled(player, config)) return false;
        JsonArray inputs = new JsonArray();
        inputs.add(textInput("code", message(player, messages, "dialog.two_factor.code", "dialog.totp.code"), 16));
        JsonArray actions = new JsonArray();
        actions.add(action(message(player, messages, "dialog.two_factor.button", "dialog.totp.button"), "2fa $(code)"));
        return show(player, dialog("multi_action",
            message(player, messages, "dialog.two_factor.title", "dialog.totp.title"),
            config.dialogShowBody() ? message(player, messages, "dialog.two_factor.body", "dialog.totp.body") : null,
            inputs, actions));
    }

    public static void clear(ServerPlayer player) {
        if (player == null) return;
        try {
            player.connection.send(ClientboundClearDialogPacket.INSTANCE);
        } catch (RuntimeException e) {
            Log.warn("Could not clear the AuthMe dialog for " + player.getName().getString(), e);
        }
    }

    private static boolean enabled(ServerPlayer player, AuthMeConfig config) {
        return player != null && config != null && config.dialogPostJoinEnabled();
    }

    private static boolean show(ServerPlayer player, JsonObject json) {
        try {
            Dialog dialog = Dialog.DIRECT_CODEC.parse(JsonOps.INSTANCE, JsonParser.parseString(json.toString()))
                .result().orElse(null);
            if (dialog == null) {
                Log.warn("AuthMe dialog was rejected by the vanilla dialog codec: " + json);
                return false;
            }
            player.connection.send(new ClientboundShowDialogPacket(Holder.direct(dialog)));
            return true;
        } catch (RuntimeException e) {
            Log.warn("Could not send an AuthMe dialog to " + player.getName().getString(), e);
            return false;
        }
    }

    private static JsonObject dialog(String type, String title, String body, JsonArray inputs, JsonArray actions) {
        JsonObject json = new JsonObject();
        json.addProperty("type", "minecraft:" + type);
        json.add("title", text(title));
        json.addProperty("pause", false);
        json.addProperty("after_action", "close");
        if (body != null && !body.isBlank()) {
            JsonArray bodies = new JsonArray();
            JsonObject plain = new JsonObject();
            plain.addProperty("type", "minecraft:plain_message");
            plain.add("contents", text(body));
            bodies.add(plain);
            json.add("body", bodies);
        }
        json.add("inputs", inputs);
        json.add("actions", actions);
        json.addProperty("columns", Math.min(2, Math.max(1, actions.size())));
        return json;
    }

    private static JsonObject action(String label, String command) {
        JsonObject button = new JsonObject();
        button.add("label", text(label));
        JsonObject run = new JsonObject();
        run.addProperty("type", "minecraft:dynamic/run_command");
        run.addProperty("template", command);
        button.add("action", run);
        return button;
    }

    private static JsonObject textInput(String key, String label, int maxLength) {
        JsonObject input = new JsonObject();
        input.addProperty("key", key);
        input.addProperty("type", "minecraft:text");
        input.add("label", text(label));
        input.addProperty("label_visible", true);
        input.addProperty("max_length", Math.max(1, Math.min(512, maxLength)));
        return input;
    }

    private static JsonObject text(String value) {
        JsonObject text = new JsonObject();
        text.addProperty("text", value == null ? "" : value.replace('&', '\u00a7'));
        return text;
    }

    private static String message(ServerPlayer player, Messages messages, String preferred, String fallback) {
        if (messages == null) return "";
        AuthMe auth = AuthMe.get();
        String value = auth == null ? messages.get(preferred) : auth.message(player, preferred);
        if (!value.startsWith("&c[missing message:")) return value;
        return auth == null ? messages.get(fallback) : auth.message(player, fallback);
    }
}
