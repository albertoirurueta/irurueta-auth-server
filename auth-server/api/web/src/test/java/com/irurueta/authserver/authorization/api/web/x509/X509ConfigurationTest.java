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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.application.x509.ResolveCertificateLoginUseCase;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * Unit tests of {@link X509Configuration}.
 */
@ExtendWith(MockitoExtension.class)
class X509ConfigurationTest {

    /** Finds the account of a fingerprint. */
    @Mock
    private ResolveCertificateLoginUseCase useCase;

    /** Loads the accounts. */
    @Mock
    private UserDetailsService userDetailsService;

    /** Adds the factor authority. */
    @Mock
    private FactorGrantor grantor;

    /** The generator of the development key store. */
    @Mock
    private ObjectProvider<DevX509KeyStore> developmentKeyStore;

    /** Configuration under test. */
    private final X509Configuration configuration = new X509Configuration();

    /**
     * Verifies that the declared beans are built.
     */
    @Test
    void beans_whenDeclared_areBuilt() {
        final var properties = properties("");

        assertNotNull(configuration.certificatePrincipalExtractor());
        assertNotNull(configuration.x509UserDetailsService(useCase, userDetailsService));
        assertNotNull(configuration.devX509KeyStore());
        assertNotNull(configuration.x509TlsKeyStoreResolver(properties, developmentKeyStore));
        assertNotNull(configuration.x509TlsConnectorCustomizer(properties,
                configuration.x509TlsKeyStoreResolver(properties, developmentKeyStore)));
    }

    /**
     * Verifies that the chain customizer is declared with its order, with and without the forwarded transport.
     *
     * @throws NoSuchMethodException if the bean method is missing.
     */
    @Test
    void x509ChainCustomizer_whenDeclared_hasItsOrder() throws NoSuchMethodException {
        final var extractor = configuration.certificatePrincipalExtractor();
        final var service = configuration.x509UserDetailsService(useCase, userDetailsService);

        final var plain = configuration.x509ChainCustomizer(extractor, service, grantor, properties(""));
        final var forwarded = configuration.x509ChainCustomizer(extractor, service, grantor,
                properties("X-Client-Cert"));

        assertInstanceOf(X509ChainCustomizer.class, plain);
        assertInstanceOf(X509ChainCustomizer.class, forwarded);
        final var method = X509Configuration.class.getMethod("x509ChainCustomizer",
                CertificatePrincipalExtractor.class, X509UserDetailsService.class, FactorGrantor.class,
                X509Properties.class);
        assertEquals(X509ChainCustomizer.ORDER, method.getAnnotation(Order.class).value());
        assertEquals(LoginChainCustomizer.class, method.getReturnType());
    }

    /**
     * Builds the settings.
     *
     * @param header the forwarded header, empty for none.
     * @return the settings.
     */
    private static X509Properties properties(final String header) {
        return new X509Properties(true, header, List.of("192.0.2.0/24"), 0, "sc", "", "", "PKCS12");
    }
}
