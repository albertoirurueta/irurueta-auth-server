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

import org.springframework.security.authorization.AuthorizationResult;

/**
 * Denial that tells {@link StepUpAccessDeniedHandler} the caller is allowed to perform the operation but must
 * authenticate again more strongly or more recently (RFC 9470), as opposed to an ordinary refusal.
 */
public record StepUpRequiredDecision() implements AuthorizationResult {

    @Override
    public boolean isGranted() {
        return false;
    }
}
