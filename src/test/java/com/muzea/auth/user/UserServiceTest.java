package com.muzea.auth.user;

import com.muzea.auth.error.AuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserService userService;

    @Test
    void registerNormalizesEmailAndPersistsUnverifiedUser() {
        when(userRepository.existsByEmailIgnoreCase("user@example.com")).thenReturn(false);
        when(userRepository.existsByUsernameIgnoreCase("user")).thenReturn(false);
        when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));

        User user = userService.register("  User@Example.com ", "user", "User");

        assertThat(user.getEmail()).isEqualTo("user@example.com");
        assertThat(user.getUsername()).isEqualTo("user");
        assertThat(user.isEmailVerified()).isFalse();
    }

    @Test
    void registerRejectsDuplicateEmail() {
        when(userRepository.existsByEmailIgnoreCase("user@example.com")).thenReturn(true);

        assertThatThrownBy(() -> userService.register("user@example.com", "user", null))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("already registered");
    }

    @Test
    void registerRejectsDuplicateUsername() {
        when(userRepository.existsByEmailIgnoreCase("user@example.com")).thenReturn(false);
        when(userRepository.existsByUsernameIgnoreCase("user")).thenReturn(true);

        assertThatThrownBy(() -> userService.register("user@example.com", "user", null))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("already taken");
    }

    @Test
    void getByIdFailsWhenMissing() {
        UUID id = UUID.randomUUID();
        when(userRepository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> userService.getById(id)).isInstanceOf(AuthException.class);
    }
}
