package com.muzea.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    private MockHttpServletRequest request(String remoteAddr, String forwardedFor) {
        var request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        if (forwardedFor != null) {
            request.addHeader("X-Forwarded-For", forwardedFor);
        }
        return request;
    }

    @Test
    void ignoresForwardedHeaderWhenProxyIsNotTrusted() {
        var resolver = new ClientIpResolver(false);

        assertThat(resolver.resolve(request("10.0.0.5", "1.2.3.4")))
                .isEqualTo("10.0.0.5");
    }

    @Test
    void usesFirstForwardedAddressWhenProxyIsTrusted() {
        var resolver = new ClientIpResolver(true);

        assertThat(resolver.resolve(request("10.0.0.5", "1.2.3.4, 10.0.0.5")))
                .isEqualTo("1.2.3.4");
    }

    @Test
    void fallsBackToRemoteAddressWhenForwardedHeaderIsBlank() {
        var resolver = new ClientIpResolver(true);

        assertThat(resolver.resolve(request("10.0.0.5", "  "))).isEqualTo("10.0.0.5");
        assertThat(resolver.resolve(request("10.0.0.5", null))).isEqualTo("10.0.0.5");
    }
}
