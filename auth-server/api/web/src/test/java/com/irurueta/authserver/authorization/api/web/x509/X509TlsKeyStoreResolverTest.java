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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

/**
 * Unit tests of {@link X509TlsKeyStoreResolver}.
 */
@ExtendWith(MockitoExtension.class)
class X509TlsKeyStoreResolverTest {

    /** The generator of the development key store, when the {@code dev} profile is active. */
    @Mock
    private ObjectProvider<DevX509KeyStore> developmentKeyStore;

    /** The generator itself. */
    @Mock
    private DevX509KeyStore generator;

    /**
     * Verifies that a configured key store wins over the generated one.
     */
    @Test
    void resolve_whenAKeyStoreIsConfigured_usesIt() {
        final var password = UUID.randomUUID().toString();
        final var resolver = new X509TlsKeyStoreResolver(
                properties("/etc/auth/server.p12", password), developmentKeyStore);

        final var keyStore = resolver.resolve();

        assertEquals(Path.of("/etc/auth/server.p12"), keyStore.location());
        assertEquals(password, keyStore.password());
        assertEquals("PKCS12", keyStore.type());
    }

    /**
     * Verifies that the generated key store is used under the development profile when none is configured.
     */
    @Test
    void resolve_whenNoneIsConfiguredAndDevIsActive_usesTheGeneratedOne() {
        final var generated = new X509TlsKeyStore(Path.of("dev.p12"), UUID.randomUUID().toString(), "PKCS12");
        when(developmentKeyStore.getIfAvailable()).thenReturn(generator);
        when(generator.load()).thenReturn(generated);

        assertSame(generated, new X509TlsKeyStoreResolver(properties("", ""), developmentKeyStore).resolve());
    }

    /**
     * Verifies that without a key store, and outside the development profile, the startup stops.
     */
    @Test
    void resolve_whenNoneIsConfiguredOutsideDev_throwsIllegalStateException() {
        when(developmentKeyStore.getIfAvailable()).thenReturn(null);
        final var resolver = new X509TlsKeyStoreResolver(properties("", ""), developmentKeyStore);

        assertThrows(IllegalStateException.class, resolver::resolve);
    }

    /**
     * Builds the settings.
     *
     * @param keyStore path of the key store.
     * @param password password of the key store.
     * @return the settings.
     */
    private static X509Properties properties(final String keyStore, final String password) {
        return new X509Properties(true, "", List.of(), 1, "sc", keyStore, password, "PKCS12");
    }
}
