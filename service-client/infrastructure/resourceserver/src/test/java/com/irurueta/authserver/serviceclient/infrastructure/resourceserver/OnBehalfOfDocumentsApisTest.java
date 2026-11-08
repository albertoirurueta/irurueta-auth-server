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

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;

/**
 * Unit tests of {@link OnBehalfOfDocumentsApis}.
 */
@ExtendWith(MockitoExtension.class)
class OnBehalfOfDocumentsApisTest {

    /** The user's token. */
    private static final String SUBJECT_TOKEN = "user-token";

    /** Builds the documents clients. */
    @Mock
    private DocumentsApis documentsApis;

    /** Documents client of the user. */
    @Mock
    private DocumentsApi documentsApi;

    /** Builds the principals; the real one. */
    @Spy
    private PrincipalMapper principalMapper;

    /** Object under test. */
    @InjectMocks
    private OnBehalfOfDocumentsApis apis;

    /**
     * Verifies that the client is built for the token exchange registration and for the principal of the user.
     */
    @Test
    void forSubject_whenCalled_buildsTheClientOfTheExchangeRegistration() {
        when(documentsApis.forPrincipal(eq(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID), any()))
                .thenReturn(documentsApi);

        assertSame(documentsApi, apis.forSubject(SUBJECT_TOKEN));

        final var principal = ArgumentCaptor.<Authentication>captor();
        verify(documentsApis)
                .forPrincipal(eq(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID), principal.capture());
        assertInstanceOf(SubjectTokenAuthentication.class, principal.getValue());
    }
}
