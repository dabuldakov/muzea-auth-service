package com.muzea.auth.token;

/** Метаданные устройства/запроса, привязанные к refresh-сессии. */
public record SessionInfo(String deviceId, String userAgent, String ip) {
}
