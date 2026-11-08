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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Registers the client certificate as an authentication factor: a strong primary one, because the holder proves
 * possession of the private key during the TLS handshake (or the proxy did on the server's behalf), so a certificate
 * satisfies the multi-factor policy on its own. It reports {@code sc} (a smart card) by default, or {@code hwk} when
 * the deployment says its certificates are bound to hardware. It exists only while the sign-in with a certificate is
 * enabled, so the registry of an ordinary deployment is unchanged.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "authserver.x509", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(X509Properties.class)
public class X509Factor {

    /** Identifier of the factor. */
    public static final String ID = "x509";

    /** Authority Spring Security grants to a client certificate. */
    public static final String AUTHORITY = FactorGrantedAuthority.X509_AUTHORITY;

    // tag::x509-factor[]
    /**
     * Declares the certificate factor.
     *
     * @param properties settings of the sign-in with a certificate, which choose the reported {@code amr} value.
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor x509AuthenticationFactor(final X509Properties properties) {
        return new AuthenticationFactor(ID, properties.amr(), AUTHORITY, FactorStrength.PRIMARY_STRONG);
    }
    // end::x509-factor[]
}
