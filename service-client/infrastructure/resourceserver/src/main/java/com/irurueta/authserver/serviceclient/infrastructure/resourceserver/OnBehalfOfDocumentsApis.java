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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Builds the documents client of a user: its requests carry the access token that the authorization server issues in
 * exchange for the user's own token.
 */
@Component
@RequiredArgsConstructor
public class OnBehalfOfDocumentsApis {

    /** Builds the documents clients. */
    private final DocumentsApis documentsApis;

    /** Builds the principals the authorized client manager caches tokens under. */
    private final PrincipalMapper principalMapper;

    /**
     * Builds the client of one user.
     *
     * @param subjectToken access token of the user, which is exchanged and never logged.
     * @return the documents client.
     */
    public DocumentsApi forSubject(final String subjectToken) {
        return documentsApis.forPrincipal(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID,
                principalMapper.user(subjectToken));
    }
}
