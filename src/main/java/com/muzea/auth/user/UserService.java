package com.muzea.auth.user;

import com.muzea.auth.error.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(normalize(email));
    }

    @Transactional(readOnly = true)
    public User getByEmail(String email) {
        return findByEmail(email)
                .orElseThrow(() -> AuthException.badRequest("user_not_found", "User not found"));
    }

    @Transactional(readOnly = true)
    public User getById(UUID id) {
        return userRepository.findById(id)
                .orElseThrow(() -> AuthException.unauthorized("user_not_found", "User not found"));
    }

    /** Создаёт неверифицированного пользователя. */
    @Transactional
    public User register(String email, String username, String displayName) {
        String normalizedEmail = normalize(email);
        if (userRepository.existsByEmailIgnoreCase(normalizedEmail)) {
            throw AuthException.conflict("email_taken", "Email is already registered");
        }
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw AuthException.conflict("username_taken", "Username is already taken");
        }
        User user = User.builder()
                .email(normalizedEmail)
                .username(username)
                .displayName(displayName)
                .emailVerified(false)
                .build();
        return userRepository.save(user);
    }

    @Transactional
    public void markEmailVerified(User user) {
        if (!user.isEmailVerified()) {
            user.setEmailVerified(true);
            userRepository.save(user);
        }
    }

    /** Удаляет аккаунт из IdP. */
    @Transactional
    public void delete(UUID id) {
        userRepository.deleteById(id);
    }

    public static String normalize(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
