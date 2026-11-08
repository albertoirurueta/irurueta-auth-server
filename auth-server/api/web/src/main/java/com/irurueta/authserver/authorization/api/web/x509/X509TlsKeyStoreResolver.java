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

import java.nio.file.Path;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.util.StringUtils;

/**
 * Decides which key store holds the server certificate of the dedicated TLS port: the configured one or, under the
 * {@code dev} profile and with none configured, the generated one. Anything else is a configuration error that stops
 * the startup, so the port is never opened with a certificate nobody chose.
 */
@RequiredArgsConstructor
public class X509TlsKeyStoreResolver {

    /** Settings of the sign-in with a certificate. */
    private final X509Properties properties;

    /** The generator of the development key store, present only under the {@code dev} profile. */
    private final ObjectProvider<DevX509KeyStore> developmentKeyStore;

    /**
     * Finds the key store.
     *
     * @return the key store.
     * @throws IllegalStateException if none is configured and the development one is not available.
     */
    public X509TlsKeyStore resolve() {
        if (StringUtils.hasText(properties.keyStore())) {
            return new X509TlsKeyStore(Path.of(properties.keyStore()), properties.keyStorePassword(),
                    properties.keyStoreType());
        }
        final var generated = developmentKeyStore.getIfAvailable();
        if (generated == null) {
            throw new IllegalStateException("authserver.x509.port needs authserver.x509.key-store (and its password) "
                    + "with the server certificate; only the dev profile generates one");
        }
        return generated.load();
    }
}
