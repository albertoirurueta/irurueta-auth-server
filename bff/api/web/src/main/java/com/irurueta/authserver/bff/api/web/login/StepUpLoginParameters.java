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
package com.irurueta.authserver.bff.api.web.login;

import java.io.Serial;
import java.io.Serializable;

/**
 * Step-up values of a login (RFC 9470), kept in the session by {@link BffLoginController} until
 * {@link StepUpAuthorizationRequestResolver} adds them to the authorization request. It is serializable because the
 * session is stored by Spring Session JDBC.
 *
 * @param acrValues space-separated authentication context class references to send as {@code acr_values}, or
 *                  {@code null} to send none.
 * @param maxAge    maximum age, in seconds, of the authentication to send as {@code max_age}, or {@code null} to send
 *                  none.
 */
public record StepUpLoginParameters(String acrValues, Long maxAge) implements Serializable {

    /** Serialization version. */
    @Serial
    private static final long serialVersionUID = 1L;
}
