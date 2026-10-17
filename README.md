# muzea-auth-service

Единый провайдер идентичности (IdP) для экосистемы muzea: регистрация по email,
passwordless-вход и выдача токенов для ресурс-сервисов (`makeup`, `chat`).

Сервис — единственное место, которое знает про аутентификацию. Остальные сервисы
проверяют выданный access-токен по JWKS и не хранят пользовательских паролей.

## Что уже реализовано (Фаза 1)

- **Регистрация по email**: создаётся неверифицированный пользователь, на почту
  уходит одноразовый код (OTP).
- **Подтверждение email**: `verify-email` активирует аккаунт и сразу выдаёт токены.
- **Passwordless-вход**: `otp/request` + `otp/verify` — вход по коду на почту.
- **Токены**:
  - access — короткоживущий JWT **RS256** (`iss`, `aud`, `sub`, `email`, `username`);
  - refresh — непрозрачный, одноразовый, с **ротацией** и обнаружением повторного
    использования (при reuse отзывается всё семейство сессии).
- **JWKS + discovery**: `/.well-known/jwks.json`, `/.well-known/openid-configuration`.
- **Сессии/устройства**: список активных сессий, отзыв сессии, выход со всех устройств.
- **Ограничения**: cooldown и лимит запросов OTP, TTL и число попыток ввода кода.

Пароля нет вовсе — это осознанный passwordless-дизайн (passkeys — Фаза 2).

## API

| Метод | Путь | Назначение |
|-------|------|------------|
| POST | `/auth/register` | Регистрация (email, username, displayName) → код на почту |
| POST | `/auth/verify-email` | Подтверждение email кодом → токены |
| POST | `/auth/resend-verification` | Повторная отправка кода подтверждения |
| POST | `/auth/otp/request` | Запрос кода для входа |
| POST | `/auth/otp/verify` | Вход по коду → токены |
| POST | `/auth/token/refresh` | Ротация refresh-токена → новая пара |
| POST | `/auth/logout` | Отзыв refresh-сессии |
| POST | `/auth/logout-all` | Отзыв всех сессий (нужен access-токен) |
| GET | `/auth/me` | Текущий пользователь (нужен access-токен) |
| GET | `/auth/sessions` | Активные сессии (нужен access-токен) |
| DELETE | `/auth/sessions/{id}` | Отозвать сессию (нужен access-токен) |
| GET | `/.well-known/jwks.json` | Публичный набор ключей подписи |
| GET | `/.well-known/openid-configuration` | Discovery-документ |

## Конфигурация

Ключевые переменные окружения (см. `.env` и `docker-compose.yaml`):

| Переменная | Описание |
|------------|----------|
| `AUTH_ISSUER` | `iss` access-токенов (например `https://auth.muzea.su`) |
| `AUTH_AUDIENCE` | Список аудиторий через запятую (`api-muzea,chat-muzea`) |
| `AUTH_RSA_PRIVATE_KEY` | base64 PKCS#8 приватный ключ (обязателен в prod) |
| `AUTH_RSA_KEY_ID` | `kid` ключа в JWKS |
| `AUTH_ACCESS_TTL_SECONDS` | Время жизни access-токена (по умолчанию 900) |
| `AUTH_REFRESH_TTL_SECONDS` | Время жизни refresh-токена (по умолчанию 30 дней) |
| `MAIL_*` | SMTP для отправки кодов |
| `APP_MAIL_ENABLED` | `false` в dev: код печатается в лог вместо отправки |

В dev, если `AUTH_RSA_PRIVATE_KEY` не задан, генерируется эфемерный ключ
(токены живут до рестарта). В prod ключ обязателен — приложение не стартует без него.

### Генерация ключа

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem
openssl pkcs8 -topk8 -nocrypt -in key.pem -outform DER | base64 -w0
```

## Локальный запуск

```bash
# PostgreSQL можно поднять из compose:
docker compose up -d postgres
SPRING_PROFILES_ACTIVE=dev APP_MAIL_ENABLED=false ./gradlew bootRun
```

В dev письма не отправляются — OTP-код виден в логе приложения.

## Тесты

```bash
./gradlew test                      # unit-тесты
./gradlew integrationTest           # интеграционные (PostgreSQL в Testcontainers)
./gradlew jacocoTestCoverageVerification   # гейт покрытия
```

## Ресурс-сервисы (следующий шаг Фазы 1)

`makeup` и `chat` должны:

1. Настроить `JwtDecoder` на JWK Set URI: `{AUTH_ISSUER}/.well-known/jwks.json`
   с валидацией `iss` и `aud`.
2. Убрать собственную логин/пароль-аутентификацию (временно — оставить как legacy).
3. Авто-провижинить локального пользователя по `sub` токена.

## Фазы

- **Ф0** — каркас сервиса, инфраструктура, CI/CD. ✅
- **Ф1** — регистрация по email + passwordless-вход, RS256/JWKS, ротация refresh. ✅
- **Ф2** — passkeys (WebAuthn) + backup-коды.
- **Ф3** — перевод ресурс-сервисов на JWKS, отказ от legacy-паролей.

## Деплой

Push в `main` запускает `.github/workflows/deploy.yml` (тесты + сборка, затем
`docker compose up -d --build` на VPS). Внешний порт — `8087` (за nginx).

## Прод

- Публичный адрес: **https://auth.muzea.su** (TLS через certbot, редирект с HTTP).
- `AUTH_ISSUER=https://auth.muzea.su`, `AUTH_AUDIENCE=api-muzea,chat-muzea`.
- Ресурс-сервисы (`makeup`, `chat`) проверяют access-токены по
  `https://auth.muzea.su/.well-known/jwks.json` и создают локального пользователя
  по claim `sub` (поле `auth_subject`); собственный вход оставлен как legacy.

