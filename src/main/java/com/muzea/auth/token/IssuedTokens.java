package com.muzea.auth.token;

import com.muzea.auth.user.User;

/** Пара токенов вместе с пользователем, для которого она выдана. */
public record IssuedTokens(TokenPair tokens, User user) {
}
