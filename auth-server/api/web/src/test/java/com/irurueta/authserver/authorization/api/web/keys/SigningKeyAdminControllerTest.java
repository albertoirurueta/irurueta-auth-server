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

package com.irurueta.authserver.authorization.api.web.keys;

import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.application.keys.ListSigningKeysUseCase;
import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Unit tests of {@link SigningKeyAdminController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class SigningKeyAdminControllerTest {

    /** Lists the keys. */
    @Mock
    private ListSigningKeysUseCase listSigningKeysUseCase;

    /** Rotates the keys. */
    @Mock
    private SigningKeyRotator signingKeyRotator;

    /** Subject under test. */
    @InjectMocks
    private SigningKeyAdminController controller;

    /** The MockMvc over the controller. */
    private MockMvc mockMvc;

    /**
     * Builds the standalone MockMvc.
     */
    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    /**
     * Listing answers the public view of every key and never the private half.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void list_whenKeysExist_returnsPublicViewOnly() throws Exception {
        when(listSigningKeysUseCase.execute()).thenReturn(List.of(key()));

        mockMvc.perform(get("/api/admin/keys"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].kid").value("kid-1"))
                .andExpect(jsonPath("$[0].status").value("ACTIVE"))
                .andExpect(jsonPath("$[0].encryptedPrivateJwk").doesNotExist());
    }

    /**
     * Rotating rotates first and then answers the keys.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void rotate_whenPosted_rotatesAndReturnsKeys() throws Exception {
        when(listSigningKeysUseCase.execute()).thenReturn(List.of(key()));

        mockMvc.perform(post("/api/admin/keys/rotate"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].kid").value("kid-1"));

        final var order = inOrder(signingKeyRotator, listSigningKeysUseCase);
        order.verify(signingKeyRotator).rotate();
        order.verify(listSigningKeysUseCase).execute();
    }

    /**
     * Builds an active key.
     *
     * @return the key.
     */
    private static SigningKey key() {
        final var created = Instant.parse("2026-01-01T00:00:00Z");
        return new SigningKey("kid-1", "RS256", "{\"kty\":\"RSA\"}", "private-part", SigningKeyStatus.ACTIVE,
                created, created, null);
    }
}
