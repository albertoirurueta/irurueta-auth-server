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
package com.irurueta.authserver.authorization.application.social;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentityRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ListIdentitiesUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ListIdentitiesUseCaseTest {

    /** Port that stores the links. */
    @Mock
    private FederatedIdentityRepository federatedIdentityRepository;

    /** Use case under test. */
    @InjectMocks
    private ListIdentitiesUseCase useCase;

    /**
     * Verifies that the links of the account are returned as the port reports them.
     */
    @Test
    void execute_whenAccountHasIdentities_returnsThem() {
        final var userId = UUID.randomUUID();
        final var identities = List.<FederatedIdentity>of();
        when(federatedIdentityRepository.findByUser(userId)).thenReturn(identities);

        assertSame(identities, useCase.execute(userId));
    }
}
