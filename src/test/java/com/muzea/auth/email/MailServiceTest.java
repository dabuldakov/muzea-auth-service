package com.muzea.auth.email;

import com.muzea.auth.config.AppProperties;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.times;

class MailServiceTest {

    private final JavaMailSender sender = mock(JavaMailSender.class);

    private AppProperties properties(boolean enabled) {
        return new AppProperties(
                new AppProperties.Cors(List.of("*")),
                new AppProperties.Mail(enabled, "no-reply@muzea.test")
        );
    }

    @Test
    void disabledMailDoesNotTouchSmtp() {
        new MailService(sender, properties(false)).sendOtp("user@muzea.test", "123456", EmailPurpose.LOGIN);

        verifyNoInteractions(sender);
    }

    @Test
    void enabledMailSendsSubjectAndCodeForEveryPurpose() {
        MailService service = new MailService(sender, properties(true));

        service.sendOtp("user@muzea.test", "111111", EmailPurpose.REGISTER);
        service.sendOtp("user@muzea.test", "222222", EmailPurpose.LOGIN);
        service.sendOtp("user@muzea.test", "333333", EmailPurpose.RECOVERY);

        ArgumentCaptor<SimpleMailMessage> captor = ArgumentCaptor.forClass(SimpleMailMessage.class);
        verify(sender, times(3)).send(captor.capture());
        List<SimpleMailMessage> messages = captor.getAllValues();

        assertThat(messages.get(0).getSubject()).contains("Подтверждение email");
        assertThat(messages.get(1).getSubject()).contains("вход");
        assertThat(messages.get(2).getSubject()).contains("Восстановление");
        assertThat(messages.get(1).getText()).contains("222222");
        assertThat(messages.get(1).getTo()).containsExactly("user@muzea.test");
        assertThat(messages.get(1).getFrom()).isEqualTo("no-reply@muzea.test");
    }
}
