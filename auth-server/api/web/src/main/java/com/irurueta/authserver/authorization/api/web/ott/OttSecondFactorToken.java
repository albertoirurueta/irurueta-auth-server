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
package com.irurueta.authserver.authorization.api.web.ott;

import java.io.Serial;
import java.util.List;
import lombok.EqualsAndHashCode;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Request to verify a one-time code as a second factor: the authentication the user already holds (the primary
 * factor), the code the user typed and the binding id of the session that requested it. It is never authenticated
 * itself; {@link OttSecondFactorAuthenticationProvider} answers with the primary authentication enriched with the
 * authority of the channel.
 */
@EqualsAndHashCode(callSuper = true)
public class OttSecondFactorToken extends AbstractAuthenticationToken {

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;

    /** The authentication the user already holds. */
    private final Authentication primary;

    /** The code as typed. */
    private final String code;

    /** Binding id of the session that requested the code. */
    private final String bindingId;

    /**
     * Creates the request.
     *
     * @param primary   the authentication the user already holds.
     * @param code      the code as typed.
     * @param bindingId binding id of the session that requested the code, empty when it requested none.
     */
    public OttSecondFactorToken(final Authentication primary, final String code, final String bindingId) {
        super(List.of());
        this.primary = primary;
        this.code = code;
        this.bindingId = bindingId;
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
     * Gets the binding id of the session that requested the code.
     *
     * @return the binding id.
     */
    public String bindingId() {
        return bindingId;
    }
}
