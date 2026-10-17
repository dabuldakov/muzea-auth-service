# План миграции на единый вход (email-код) и выпиливания legacy

Цель: все пользователи входят через `auth-service` (passwordless, код на email).
Старые парольные входы (`makeup` и `chat`) убираем **после** того, как по БД
увидим, что реальные пользователи перешли и подтвердили email.

## Подход (простой)
1. **Линк при первом входе** уже включён: `auth_subject` → email → **username**
   (фолбэк, `AUTH_OIDC_LINK_BY_USERNAME`, по умолчанию `true`). Если человек
   регистрируется в новой версии с прежним email **или** прежним username, его
   существующий аккаунт в chat/makeup привязывается — сообщения и контакты
   сохраняются.
2. Приложение показывает попап: «Вход теперь по коду на email. Если у вас уже
   был аккаунт — нажмите "Зарегистрироваться", укажите **прежние email и
   username**, придёт код подтверждения; данные сохранятся.»
3. Пользователи обновляют приложение и входят по коду. Старый парольный вход
   продолжает работать для не обновившихся (окно совместимости — управляемое).
4. Когда по БД видим, что все реальные пользователи подтвердили email — выпиливаем
   legacy.

## Проверка по БД (перед отсечением)
На сервере приложений:

```bash
# auth-service: сколько пользователей подтвердили email
docker exec muzea-auth-service-postgres-1 psql -U admin -d auth_db -c \
  "SELECT count(*) FILTER (WHERE email_verified) AS verified, count(*) AS total FROM users;"

# chat: сколько локальных пользователей привязано к IdP (auth_subject) и сколько ещё legacy
docker exec chat-backend-postgres-1 psql -U admin -d chat_db -c \
  "SELECT count(*) FILTER (WHERE auth_subject IS NOT NULL) AS linked,
          count(*) FILTER (WHERE auth_subject IS NULL) AS legacy
   FROM users WHERE is_deleted = false;"

# makeup: то же
MP=$(grep '^POSTGRES_USERNAME=' /root/makeup-backend/.env | cut -d= -f2)
MDB=$(grep '^POSTGRES_DB=' /root/makeup-backend/.env | cut -d= -f2)
docker exec makeup-backend-postgres-1 psql -U "$MP" -d "$MDB" -c \
  "SELECT count(*) FILTER (WHERE auth_subject IS NOT NULL) AS linked,
          count(*) FILTER (WHERE auth_subject IS NULL) AS legacy
   FROM users;"
```

Плюс сверить, что среди `legacy` не остаётся «живых» (кто реально пользуется):
наличие сессий/сообщений за последнее время. Простаивающие legacy-аккаунты
можно отсекать.

## Фаза F3 — что выпилить (после проверки)
**chat**
- Эндпоинты `/api/auth/login|register|refresh|forgot-password|reset-password|verify-email` + вся логика паролей/сессий (`AuthService`, `UserSession*`, `JwtUtil`/`JwtAuthenticationFilter` HS256-ветку).
- `user_sessions`, колонку `password_hash`, поля `reset_token`, `email_verification_token`.
- Приём HS256 в фильтре (оставить только RS256/JWKS).

**makeup**
- `POST /auth/login|register`, `AuthController`/`UserService` парольную часть, `JwtService`/HS256-фильтр (оставить RS256/JWKS).
- Колонку `password_hash`.

**приложение**
- `SecureStore` ключ `account_password`, legacy-миграции пароля/токена, остатки `AuthApi`.

## Обратная совместимость
| | До F3 | После F3 |
|---|---|---|
| Старое приложение (пароль) | работает | **не работает** (нужно обновиться) |
| Новое приложение (email-код) | работает | работает |
| Данные (переписки/контакты) | сохраняются при линке email/username | сохраняются |

## Порядок
1. ✅ Линк email → username.
2. Релиз нового приложения (попап + email-код + фикс refresh + удаление IdP-аккаунта).
3. Окно совместимости; следим по БД за подтверждёнными email.
4. F3: выпиливание legacy (отдельным релизом/деплоем), с проверкой, что не осталось активных legacy-пользователей.
