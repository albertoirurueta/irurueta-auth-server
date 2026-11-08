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

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.passkeys.AccountStatusUserDetailsService;
import com.irurueta.authserver.authorization.application.x509.ResolveCertificateLoginUseCase;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;

/**
 * Installs the sign-in with a client certificate in the login/UI chain, only while
 * {@code authserver.x509.enabled} is {@code true}. Nothing outside this feature is edited: the chain applies every
 * {@link LoginChainCustomizer} bean, in order, before its catch-all rule.
 */
@Configuration(value = "x509WebConfiguration", proxyBeanMethods = false)
@ConditionalOnProperty(prefix = "authserver.x509", name = "enabled", havingValue = "true")
public class X509Configuration {

    /**
     * Declares the extractor that takes the fingerprint of the certificate as the principal.
     *
     * @return the extractor.
     */
    @Bean
    public CertificatePrincipalExtractor certificatePrincipalExtractor() {
        return new CertificatePrincipalExtractor();
    }

    /**
     * Declares the service that loads the account a certificate is bound to, refusing one that cannot sign in.
     *
     * @param useCase            finds the account of a fingerprint.
     * @param userDetailsService loads the accounts.
     * @return the service.
     */
    @Bean
    public X509UserDetailsService x509UserDetailsService(
            final ResolveCertificateLoginUseCase useCase, final UserDetailsService userDetailsService) {
        return new X509UserDetailsService(useCase, new AccountStatusUserDetailsService(userDetailsService));
    }

    /**
     * Declares the generator of the development key store of the TLS port, only under the {@code dev} profile.
     *
     * @return the generator.
     */
    @Bean
    @Profile("dev")
    public DevX509KeyStore devX509KeyStore() {
        return new DevX509KeyStore();
    }

    /**
     * Declares the resolver of the key store of the TLS port.
     *
     * @param properties         settings of the sign-in with a certificate.
     * @param developmentKeyStore the generator of the development key store, when the {@code dev} profile is active.
     * @return the resolver.
     */
    @Bean
    public X509TlsKeyStoreResolver x509TlsKeyStoreResolver(
            final X509Properties properties, final ObjectProvider<DevX509KeyStore> developmentKeyStore) {
        return new X509TlsKeyStoreResolver(properties, developmentKeyStore);
    }

    /**
     * Declares the customizer that adds the dedicated TLS port, which does nothing while no port is configured.
     *
     * @param properties       settings of the sign-in with a certificate.
     * @param keyStoreResolver finds the key store of the port.
     * @return the customizer.
     */
    @Bean
    public X509TlsConnectorCustomizer x509TlsConnectorCustomizer(
            final X509Properties properties, final X509TlsKeyStoreResolver keyStoreResolver) {
        return new X509TlsConnectorCustomizer(properties, keyStoreResolver);
    }

    /**
     * Declares the check that refuses a forwarded certificate while the server rewrites the address of its clients.
     *
     * @param properties  settings of the sign-in with a certificate.
     * @param environment environment of the application, with the forwarded-header strategy.
     * @return the check, which has already passed.
     */
    @Bean
    public X509ForwardedHeadersGuard x509ForwardedHeadersGuard(
            final X509Properties properties, final Environment environment) {
        return new X509ForwardedHeadersGuard(properties, environment);
    }

    /**
     * Declares the button of the sign-in with a certificate on the login page.
     *
     * @param properties settings of the sign-in with a certificate, which tell where the form posts.
     * @return the fragment.
     */
    @Bean
    public X509LoginMethodFragment x509LoginMethodFragment(final X509Properties properties) {
        return new X509LoginMethodFragment(properties);
    }

    // tag::x509-chain-customizer[]
    /**
     * Declares the customizer that enables {@code http.x509(...)}. It is applied after the social login one.
     *
     * @param extractor          takes the fingerprint of the certificate.
     * @param userDetailsService loads the account of the certificate.
     * @param grantor            adds the factor authority.
     * @param properties         settings, which tell whether a proxy may forward the certificate.
     * @return the customizer.
     */
    @Bean
    @Order(X509ChainCustomizer.ORDER)
    public LoginChainCustomizer x509ChainCustomizer(final CertificatePrincipalExtractor extractor,
            final X509UserDetailsService userDetailsService, final FactorGrantor grantor,
            final X509Properties properties) {
        final var securityContextRepository = new DelegatingSecurityContextRepository(
                new RequestAttributeSecurityContextRepository(), new HttpSessionSecurityContextRepository());
        final var successHandler = new X509AuthenticationSuccessHandler(
                grantor, securityContextRepository, new SavedRequestAwareAuthenticationSuccessHandler());
        final var forwarded = properties.forwardedEnabled() ? new ForwardedCertificateFilter(properties) : null;
        return new X509ChainCustomizer(new X509LoginFilter(), extractor, userDetailsService, forwarded,
                successHandler);
    }
    // end::x509-chain-customizer[]
}
