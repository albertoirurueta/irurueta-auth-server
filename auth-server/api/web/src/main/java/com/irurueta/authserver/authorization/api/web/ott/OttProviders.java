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

import org.springframework.security.authentication.AuthenticationProvider;

/**
 * The authentication providers of the one-time token methods, held together. They are deliberately not declared as
 * {@link AuthenticationProvider} beans: Spring Security takes a single such bean as the parent of every authentication
 * manager, and the second-factor provider belongs to its own filter's manager only.
 *
 * @param link         confirms a magic link ({@link OttLinkAuthenticationProvider}).
 * @param code         signs a user in with a numeric code ({@link OttCodeAuthenticationProvider}).
 * @param secondFactor verifies a numeric code as a second factor ({@link OttSecondFactorAuthenticationProvider}).
 */
public record OttProviders(AuthenticationProvider link, AuthenticationProvider code,
                           AuthenticationProvider secondFactor) {
}
