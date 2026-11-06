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

package com.irurueta.authserver.authorization.api.web.consent;

import java.util.List;

/**
 * View model of the consent page.
 *
 * @param clientId         identifier of the client that asks for access.
 * @param clientName       human readable name of the client.
 * @param principalName    name of the signed-in user.
 * @param state            state of the authorization request, posted back with the decision.
 * @param scopesToApprove  scopes the user is asked to approve.
 * @param approvedScopes   scopes the user granted to the client earlier.
 */
public record ConsentPageModel(
        String clientId, String clientName, String principalName, String state, List<ScopeView> scopesToApprove,
        List<ScopeView> approvedScopes) {

    /**
     * Copies the lists.
     */
    public ConsentPageModel {
        scopesToApprove = List.copyOf(scopesToApprove);
        approvedScopes = List.copyOf(approvedScopes);
    }

    /**
     * A scope and its description.
     *
     * @param name        name of the scope, which is the value posted back.
     * @param description description shown to the user.
     */
    public record ScopeView(String name, String description) {
    }
}
