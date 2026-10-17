package com.muzea.auth.email;

/** Назначение одноразового кода. */
public enum EmailPurpose {
    /** Подтверждение email при регистрации. */
    REGISTER,
    /** Passwordless-вход по коду на почту. */
    LOGIN,
    /** Восстановление доступа. */
    RECOVERY
}
