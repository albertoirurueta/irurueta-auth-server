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

package com.irurueta.authserver.bff.session;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.jdbc.config.annotation.web.http.EnableJdbcHttpSession;
import org.springframework.session.web.http.CookieSerializer;
import org.springframework.session.web.http.DefaultCookieSerializer;

/**
 * Stores the HTTP session of the BFF in PostgreSQL (Spring Session JDBC, table {@code spring_session} owned by the
 * Flyway migration {@code V300}) and names its cookie with the {@code __Host-} prefix.
 *
 * <p>This is composition-root wiring: it lives in {@code boot} because {@code spring-jdbc} is banned from
 * {@code api/web} by the enforcer rule of that module. The session holds the OAuth2 tokens of the user (the authorized
 * client), which therefore never reach the browser; the cookie is only a handle to them.
 */
@Configuration(proxyBeanMethods = false)
@EnableJdbcHttpSession
public class SessionConfiguration {

    /** Name of the session cookie; the {@code __Host-} prefix makes browsers require Secure, Path=/ and no Domain. */
    static final String COOKIE_NAME = "__Host-SESSION";

    // tag::bff-session[]
    /**
     * Builds the serializer of the session cookie: Secure, HttpOnly, SameSite=Lax, path {@code /} and no domain, which
     * is exactly what the {@code __Host-} prefix demands (the browser rejects the cookie otherwise).
     *
     * @return the cookie serializer.
     */
    @Bean
    CookieSerializer cookieSerializer() {
        final var serializer = new DefaultCookieSerializer();
        serializer.setCookieName(COOKIE_NAME);
        serializer.setUseSecureCookie(true);
        serializer.setUseHttpOnlyCookie(true);
        serializer.setSameSite("Lax");
        serializer.setCookiePath("/");
        return serializer;
    }
    // end::bff-session[]
}
