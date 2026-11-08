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

import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpClientSettings;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Builds the HTTP request factory that presents the client certificate: the one of the SSL bundle named by {@code
 * service-client.auth.ssl-bundle}. It is used for the token endpoint and for the resource server, whose tokens may be
 * bound to that certificate.
 */
@Component
@RequiredArgsConstructor
public class SslRequestFactories {

    /** Settings of the service client at the authorization server. */
    private final ServiceClientAuthProperties properties;

    /** The SSL bundles of the application, when SSL is configured at all. */
    private final ObjectProvider<SslBundles> sslBundles;

    /**
     * Builds a request factory over the configured SSL bundle.
     *
     * @return the factory, or empty when no bundle is configured and the authentication method does not need one.
     * @throws IllegalStateException if a mutual TLS method is configured without a bundle, or the bundle does not
     *                               exist.
     */
    public Optional<ClientHttpRequestFactory> create() {
        if (!StringUtils.hasText(properties.sslBundle())) {
            if (properties.method().isMutualTls()) {
                throw new IllegalStateException("service-client.auth.ssl-bundle is required for the "
                        + properties.method() + " authentication method");
            }
            return Optional.empty();
        }
        final var bundles = sslBundles.getIfAvailable();
        if (bundles == null) {
            throw new IllegalStateException("No SSL bundle is configured (spring.ssl.bundle.*)");
        }
        final var settings = HttpClientSettings.ofSslBundle(bundles.getBundle(properties.sslBundle()));
        return Optional.of(ClientHttpRequestFactoryBuilder.detect().build(settings));
    }
}
