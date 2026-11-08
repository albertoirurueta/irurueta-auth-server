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

import com.irurueta.authserver.authorization.application.x509.ResolveCertificateLoginUseCase;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

// tag::x509-user-details[]
/**
 * Loads the account a client certificate is bound to. The principal of the pre-authenticated token is the fingerprint
 * the {@link CertificatePrincipalExtractor} took, which {@link ResolveCertificateLoginUseCase} maps to the account;
 * the account is then loaded through a {@link UserDetailsService} that refuses a disabled, locked or expired one, as
 * the other sign-in methods do.
 */
@RequiredArgsConstructor
public class X509UserDetailsService implements AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    /** Finds the account a certificate is bound to. */
    private final ResolveCertificateLoginUseCase resolveCertificateLoginUseCase;

    /** Loads the account, refusing one that cannot sign in. */
    private final UserDetailsService userDetailsService;

    /**
     * Loads the account of a certificate.
     *
     * @param token the token whose principal is the fingerprint of the certificate.
     * @return the account.
     * @throws UsernameNotFoundException if the certificate is not bound to any account.
     * @throws org.springframework.security.authentication.AccountStatusException if the account cannot sign in.
     */
    @Override
    public UserDetails loadUserDetails(final PreAuthenticatedAuthenticationToken token)
            throws UsernameNotFoundException {
        final var account = resolveCertificateLoginUseCase.execute(String.valueOf(token.getPrincipal()))
                .orElseThrow(() -> new UsernameNotFoundException("The certificate is not bound to an account"));
        return userDetailsService.loadUserByUsername(account.username());
    }
}
// end::x509-user-details[]
