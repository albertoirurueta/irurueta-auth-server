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
 * user typed. It is never authenticated itself; {@link TotpAuthenticationProvider} answers with the primary
 * authentication enriched with the TOTP authority.
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

    /** Whether the code is a recovery code instead of a TOTP code. */
    private final boolean recovery;

    /**
     * Creates the request.
     *
     * @param primary  the authentication the user already holds.
     * @param code     the code as typed.
     * @param recovery whether the code is a recovery code instead of a TOTP code.
     */
    public TotpAuthenticationToken(final Authentication primary, final String code, final boolean recovery) {
        super(List.of());
        this.primary = primary;
        this.code = code;
        this.recovery = recovery;
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
     * Tells whether the code is a recovery code.
     *
     * @return {@code true} for a recovery code, {@code false} for a TOTP code.
     */
    public boolean isRecovery() {
        return recovery;
    }
}
