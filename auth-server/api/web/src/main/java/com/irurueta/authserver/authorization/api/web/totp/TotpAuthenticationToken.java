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

package com.irurueta.authserver.authorization.api.web.totp;

import java.io.Serial;
import java.util.List;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Request to verify a second factor: the authentication the user already holds (the primary factor) and the code the
 * user typed, and what kind of code it is. It is never authenticated itself; {@link TotpAuthenticationProvider} answers
 * with the primary authentication enriched with the TOTP authority and, when the code confirmed an enrolment, hands the
 * new recovery codes back to the filter through {@link #issueRecoveryCodes(List)}.
 */
@EqualsAndHashCode(callSuper = true)
public class TotpAuthenticationToken extends AbstractAuthenticationToken {

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;

    /** The authentication the user already holds. */
    private final Authentication primary;

    /** The code as typed. */
    private final String code;

    /** What kind of code it is. */
    private final TotpCodeKind kind;

    /**
     * Recovery codes generated while the request was verified (an enrolment), to be shown once; never serialized, as
     * they only travel from the provider back to the filter of the same request.
     */
    @EqualsAndHashCode.Exclude
    private transient List<String> issuedRecoveryCodes;

    /**
     * Creates the request.
     *
     * @param primary the authentication the user already holds.
     * @param code    the code as typed.
     * @param kind    what kind of code it is.
     */
    public TotpAuthenticationToken(final Authentication primary, final String code, final TotpCodeKind kind) {
        super(List.of());
        this.primary = primary;
        this.code = code;
        this.kind = kind;
    }

    /**
     * Gets the code.
     *
     * @return the code as typed.
     */
    @Override
    public String getCredentials() {
        return code;
    }

    /**
     * Gets the principal.
     *
     * @return the principal of the primary authentication.
     */
    @Override
    public Object getPrincipal() {
        return primary.getPrincipal();
    }

    /**
     * Gets the authentication the user already holds.
     *
     * @return the primary authentication.
     */
    public Authentication primary() {
        return primary;
    }

    /**
     * Tells what kind of code it is.
     *
     * @return the kind of code.
     */
    public TotpCodeKind kind() {
        return kind;
    }

    /**
     * Gets the recovery codes generated while the request was verified.
     *
     * @return the codes; empty unless the code confirmed an enrolment.
     */
    public List<String> issuedRecoveryCodes() {
        return issuedRecoveryCodes == null ? List.of() : issuedRecoveryCodes;
    }

    /**
     * Hands back the recovery codes generated while the request was verified.
     *
     * @param codes the codes in clear text.
     */
    public void issueRecoveryCodes(final List<String> codes) {
        issuedRecoveryCodes = List.copyOf(codes);
    }
}
