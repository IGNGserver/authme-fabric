package io.github.authme.platform.paper;

import net.kyori.adventure.key.Key;

/** Custom actions used only while a Paper player is still in the configuration phase. */
final class PaperDialogActionKeys {

    static final Key PRE_JOIN_LOGIN_SUBMIT = Key.key("authme:prejoin-login/submit");
    static final Key PRE_JOIN_LOGIN_CANCEL = Key.key("authme:prejoin-login/cancel");
    static final Key PRE_JOIN_LOGIN_RECOVERY = Key.key("authme:prejoin-login/recovery");
    static final Key PRE_JOIN_RECOVERY_SUBMIT = Key.key("authme:prejoin-recovery/submit");
    static final Key PRE_JOIN_RECOVERY_CANCEL = Key.key("authme:prejoin-recovery/cancel");
    static final Key PRE_JOIN_REGISTER_SUBMIT = Key.key("authme:prejoin-register/submit");
    static final Key PRE_JOIN_REGISTER_CANCEL = Key.key("authme:prejoin-register/cancel");

    private PaperDialogActionKeys() { }
}
