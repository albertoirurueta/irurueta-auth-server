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

/**
 * Request to sign in with a numeric one-time code: the code the user typed, the identifier it was requested for and the
 * binding id of the session that requested it. It is never authenticated itself; {@link OttCodeAuthenticationProvider}
 * answers with the authentication of the user.
 */
@EqualsAndHashCode(callSuper = true)
public class OttCodeAuthenticationToken extends AbstractAuthenticationToken {

    /** Longest numeric code accepted, so a token value of digits is never mistaken for a code by length alone. */
    static final int MAX_CODE_LENGTH = 12;

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;

    /** The identifier the code was requested for. */
    private final String username;

    /** The code as typed. */
    private final String code;

    /** Binding id of the session that requested the code. */
    private final String bindingId;

    /**
     * Creates the request.
     *
     * @param username  the identifier the code was requested for, empty when the session requested none.
     * @param code      the code as typed.
     * @param bindingId binding id of the session that requested the code, empty when it requested none.
     */
    public OttCodeAuthenticationToken(final String username, final String code, final String bindingId) {
        super(List.of());
        this.username = username;
        this.code = code;
        this.bindingId = bindingId;
    }

    /**
     * Tells whether a submitted value is a numeric code rather than the token of a magic link (which is a UUID).
     *
     * @param value the value of the {@code token} field.
     * @return {@code true} for one to {@value #MAX_CODE_LENGTH} ASCII digits.
     */
    public static boolean isCode(final String value) {
        return value != null && !value.isEmpty() && value.length() <= MAX_CODE_LENGTH
                && value.chars().allMatch(character -> character >= '0' && character <= '9');
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
     * Gets the identifier the code was requested for.
     *
     * @return the identifier.
     */
    @Override
    public String getPrincipal() {
        return username;
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
