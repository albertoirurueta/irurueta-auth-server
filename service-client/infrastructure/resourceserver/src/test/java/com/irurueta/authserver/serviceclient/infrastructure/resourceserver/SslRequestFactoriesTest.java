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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;

/**
 * Unit tests of {@link SslRequestFactories}.
 */
@ExtendWith(MockitoExtension.class)
class SslRequestFactoriesTest {

    /** Name of the SSL bundle. */
    private static final String BUNDLE = "service-client";

    /** The SSL bundles of the application, when there are any. */
    @Mock
    private ObjectProvider<SslBundles> sslBundles;

    /**
     * Verifies that without a bundle and with a method that needs none there is no factory.
     */
    @Test
    void create_whenNoBundleAndMethodNeedsNone_isEmpty() {
        final var factories = new SslRequestFactories(properties(AuthMethod.CLIENT_SECRET_BASIC, " "), sslBundles);

        assertTrue(factories.create().isEmpty());
        verifyNoInteractions(sslBundles);
    }

    /**
     * Verifies that a mutual TLS method without a bundle is refused.
     */
    @Test
    void create_whenMutualTlsWithoutBundle_throwsIllegalStateException() {
        final var factories = new SslRequestFactories(properties(AuthMethod.TLS_CLIENT_AUTH, null), sslBundles);

        assertThrows(IllegalStateException.class, factories::create);
    }

    /**
     * Verifies that a bundle name without any SSL configuration is refused.
     */
    @Test
    void create_whenBundleNamedButSslNotConfigured_throwsIllegalStateException() {
        when(sslBundles.getIfAvailable()).thenReturn(null);
        final var factories = new SslRequestFactories(properties(AuthMethod.TLS_CLIENT_AUTH, BUNDLE), sslBundles);

        assertThrows(IllegalStateException.class, factories::create);
    }

    /**
     * Verifies that a request factory is built over the named bundle.
     */
    @Test
    void create_whenBundleExists_buildsAFactoryOverIt() {
        final var bundles = mock(SslBundles.class);
        when(sslBundles.getIfAvailable()).thenReturn(bundles);
        when(bundles.getBundle(BUNDLE)).thenReturn(SslBundle.of(SslStoreBundle.NONE));
        final var factories = new SslRequestFactories(properties(AuthMethod.TLS_CLIENT_AUTH, BUNDLE), sslBundles);

        assertTrue(factories.create().isPresent());
    }

    /**
     * Builds the settings.
     *
     * @param method the authentication method.
     * @param bundle the name of the SSL bundle, or {@code null}.
     * @return the settings.
     */
    private static ServiceClientAuthProperties properties(final AuthMethod method, final String bundle) {
        return new ServiceClientAuthProperties(method, null, null, URI.create("https://auth.example.com/token"),
                List.of("a"), Duration.ZERO, false, bundle);
    }
}
