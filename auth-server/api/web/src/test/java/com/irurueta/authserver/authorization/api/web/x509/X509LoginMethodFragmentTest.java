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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Unit tests of {@link X509LoginMethodFragment}.
 */
class X509LoginMethodFragmentTest {

    /** The documented position of the fragment. */
    private static final int EXPECTED_ORDER = 260;

    /** Port of the dedicated TLS connector of the tests. */
    private static final int TLS_PORT = 9443;

    /** Port of the main connector of the tests. */
    private static final int MAIN_PORT = 9000;

    /** Host the page is requested on. */
    private static final String HOST = "auth.example.com";

    /**
     * Forgets the request bound to the thread.
     */
    @AfterEach
    void resetRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    /**
     * Verifies the template, the fragment and the order.
     */
    @Test
    void accessors_returnTheTemplateFragmentAndOrder() {
        final var fragment = new X509LoginMethodFragment(properties("", 0));

        assertEquals("login-x509", fragment.templateName());
        assertEquals("login", fragment.fragmentName());
        assertEquals(EXPECTED_ORDER, fragment.order());
        assertEquals(EXPECTED_ORDER, X509LoginMethodFragment.ORDER);
        assertEquals("login-x509 :: login", fragment.reference());
    }

    /**
     * Verifies that with a proxy that forwards the certificate the form posts to the relative path, with the context
     * path, even when a TLS port is configured too.
     */
    @Test
    void action_whenAProxyForwardsTheCertificate_isTheRelativePath() {
        final var fragment = new X509LoginMethodFragment(properties("X-Client-Cert", TLS_PORT));

        assertEquals("/auth/login/x509", fragment.action(request(MAIN_PORT)));
    }

    /**
     * Verifies that with only the TLS port, a page of another port posts to the TLS port of the same host.
     */
    @Test
    void action_whenOnlyTheTlsPortIsOnAndThePageIsElsewhere_isTheTlsPortOfTheSameHost() {
        final var fragment = new X509LoginMethodFragment(properties("", TLS_PORT));

        assertEquals("https://" + HOST + ":" + TLS_PORT + "/auth/login/x509", fragment.action(request(MAIN_PORT)));
    }

    /**
     * Verifies that a page served on the TLS port posts to the relative path.
     */
    @Test
    void action_whenThePageIsServedOnTheTlsPort_isTheRelativePath() {
        final var fragment = new X509LoginMethodFragment(properties("", TLS_PORT));

        assertEquals("/auth/login/x509", fragment.action(request(TLS_PORT)));
    }

    /**
     * Verifies that without any TLS port the form posts to the relative path.
     */
    @Test
    void action_whenThereIsNoTlsPort_isTheRelativePath() {
        final var fragment = new X509LoginMethodFragment(properties("", 0));

        assertEquals("/auth/login/x509", fragment.action(request(MAIN_PORT)));
    }

    /**
     * Verifies that the action of the page being rendered is computed from the request bound to the thread.
     */
    @Test
    void action_whenARequestIsBound_usesIt() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request(MAIN_PORT)));
        final var fragment = new X509LoginMethodFragment(properties("", TLS_PORT));

        assertEquals("https://" + HOST + ":" + TLS_PORT + "/auth/login/x509", fragment.action());
    }

    /**
     * Verifies that without a request bound to the thread the action is the plain path.
     */
    @Test
    void action_whenNoRequestIsBound_isThePlainPath() {
        final var fragment = new X509LoginMethodFragment(properties("", TLS_PORT));

        assertEquals("/login/x509", fragment.action());
    }

    /**
     * Builds the settings.
     *
     * @param header the forwarded header, empty for none.
     * @param port   the TLS port, {@code 0} for none.
     * @return the settings.
     */
    private static X509Properties properties(final String header, final int port) {
        return new X509Properties(true, header, List.of("192.0.2.0/24"), port, "sc", "", "", "PKCS12");
    }

    /**
     * Builds the request of the login page.
     *
     * @param localPort port of the connector the request arrived on.
     * @return the request.
     */
    private static MockHttpServletRequest request(final int localPort) {
        final var request = new MockHttpServletRequest("GET", "/auth/login");
        request.setContextPath("/auth");
        request.setServerName(HOST);
        request.setLocalPort(localPort);
        return request;
    }
}
