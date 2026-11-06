/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.irurueta.authserver.authorization.api.web.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;

/**
 * Unit tests of {@link LogoutChainCustomizer}.
 */
class LogoutChainCustomizerTest {

    /**
     * Verifies that logout is a POST to /logout that invalidates the session, deletes its cookie and returns to the
     * login page.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_configuresLogout() {
        final var http = mock(HttpSecurity.class);
        final var logout = mock(LogoutConfigurer.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<LogoutConfigurer<HttpSecurity>>>captor();

        new LogoutChainCustomizer().customize(http);

        verify(http).logout(captor.capture());
        captor.getValue().customize(logout);
        verify(logout).logoutUrl("/logout");
        verify(logout).logoutSuccessUrl("/login?logout");
        verify(logout).invalidateHttpSession(true);
        verify(logout).deleteCookies("JSESSIONID");
        assertEquals("/logout", LogoutChainCustomizer.LOGOUT_PATH);
    }
}
