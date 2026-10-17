package com.muzea.auth.email;

import com.muzea.auth.config.AppProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

/**
 * Отправка писем. Когда {@code app.mail.enabled=false} (dev/CI) письма не
 * уходят — код печатается в лог, чтобы можно было пройти флоу локально.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class MailService {

    private final JavaMailSender mailSender;
    private final AppProperties appProperties;

    public void sendOtp(String to, String code, EmailPurpose purpose) {
        String subject = subject(purpose);
        String body = "Ваш код подтверждения: " + code + "\n\n"
                + "Код действует ограниченное время. Если это были не вы — проигнорируйте письмо.";
        send(to, subject, body);
    }

    private void send(String to, String subject, String body) {
        if (!appProperties.mail().enabled()) {
            log.info("[MAIL DISABLED] to={} subject={} body={}", to, subject, body);
            return;
        }
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(appProperties.mail().from());
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
        log.info("Email sent to {} subject={}", to, subject);
    }

    private String subject(EmailPurpose purpose) {
        return switch (purpose) {
            case REGISTER -> "Подтверждение email — muzea";
            case LOGIN -> "Код для входа — muzea";
            case RECOVERY -> "Восстановление доступа — muzea";
        };
    }
}
