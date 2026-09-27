package io.github.authme.fabric.auth;

/**
 * Resolves the action after a failed password attempt.
 *
 * <p>The order is intentional: a configured temporary ban must take precedence over
 * the ordinary kick and captcha actions.  Keeping this decision independent of Minecraft
 * objects makes the precedence regression-testable for every supported Fabric line.</p>
 */
public final class LoginFailurePolicy {

    public enum Action {
        TEMPBAN,
        CAPTCHA,
        KICK_WRONG_PASSWORD,
        NONE
    }

    private LoginFailurePolicy() {
    }

    public static Action decide(boolean tempbanEnabled, int attempts, int tempbanThreshold,
                                boolean captchaEnabled, int captchaThreshold,
                                boolean kickOnWrongPassword) {
        if (tempbanEnabled && attempts >= Math.max(1, tempbanThreshold)) {
            return Action.TEMPBAN;
        }
        if (captchaEnabled && attempts >= Math.max(1, captchaThreshold)) {
            return Action.CAPTCHA;
        }
        return kickOnWrongPassword ? Action.KICK_WRONG_PASSWORD : Action.NONE;
    }
}
