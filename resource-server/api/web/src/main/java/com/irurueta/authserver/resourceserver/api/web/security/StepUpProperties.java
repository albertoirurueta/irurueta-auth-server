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

package com.irurueta.authserver.resourceserver.api.web.security;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.util.StringUtils;

/**
 * Step-up authentication policy (RFC 9470) of the sensitive operations, bound from
 * {@code resourceserver.step-up.*}.
 *
 * @param enabled   whether the policy is enforced; when {@code false} every caller is let through.
 * @param acrValues the space-separated authentication context class references the token's {@code acr} claim must
 *                  be one of; the step-up challenge advertises the whole list.
 * @param maxAge    how long ago, at most, the user must have authenticated ({@code auth_time} claim).
 */
// tag::resource-server-step-up-properties[]
@ConfigurationProperties("resourceserver.step-up")
public record StepUpProperties(
        @DefaultValue("true") boolean enabled,
        @DefaultValue("urn:irurueta:acr:mfa") String acrValues,
        @DefaultValue("PT5M") Duration maxAge) {

    /**
     * Validates the policy.
     *
     * @throws IllegalArgumentException if {@code acrValues} is blank or {@code maxAge} is not positive.
     */
    public StepUpProperties {
        if (!StringUtils.hasText(acrValues)) {
            throw new IllegalArgumentException("resourceserver.step-up.acr-values must not be blank");
        }
        if (maxAge == null || maxAge.isNegative() || maxAge.isZero()) {
            throw new IllegalArgumentException("resourceserver.step-up.max-age must be positive");
        }
    }
}
// end::resource-server-step-up-properties[]
