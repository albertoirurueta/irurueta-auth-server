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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Registers a passkey (WebAuthn credential) as an authentication factor: a strong primary one, because the
 * authenticator proves possession of the key and, with user verification, the user as well, so it satisfies the
 * multi-factor policy on its own. A user who signed in with a password and then presents a passkey on the
 * second-factor page ends up with both factors (Spring Security merges the factor authorities of the session into the
 * result of the WebAuthn filter), and the tokens report {@code pwd}, {@code hwk} and {@code mfa}.
 */
@Configuration(proxyBeanMethods = false)
public class PasskeyFactor {

    /** Identifier of the factor. */
    public static final String ID = "passkey";

    /**
     * RFC 8176 {@code amr} value of a proof of possession of a key held in hardware (or in a platform authenticator).
     * A synchronised passkey is reported the same way; the backup flags are exposed by the account API.
     */
    public static final String AMR_VALUE = "hwk";

    /** Authority Spring Security's WebAuthn provider grants once a passkey assertion has been verified. */
    public static final String AUTHORITY = FactorGrantedAuthority.WEBAUTHN_AUTHORITY;

    // tag::passkeys-factor[]
    /**
     * Declares the passkey factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor passkeyAuthenticationFactor() {
        return new AuthenticationFactor(ID, AMR_VALUE, AUTHORITY, FactorStrength.PRIMARY_STRONG);
    }
    // end::passkeys-factor[]
}
