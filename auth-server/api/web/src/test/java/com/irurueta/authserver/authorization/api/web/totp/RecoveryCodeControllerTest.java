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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

/**
 * Unit tests of {@link RecoveryCodeController}, with a standalone MockMvc.
 */
@ExtendWith(MockitoExtension.class)
class RecoveryCodeControllerTest {

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Generates the codes. */
    @Mock
    private GenerateRecoveryCodesUseCase generateRecoveryCodesUseCase;

    /** Real mapper. */
    @Spy
    private TotpDtoMapper totpDtoMapper = new TotpDtoMapper();

    /** Controller under test. */
    @InjectMocks
    private RecoveryCodeController controller;

    /**
     * Verifies that the new codes are answered, never cached.
     *
     * @throws Exception if the request fails.
     */
    @Test
    void generateRecoveryCodes_whenCalled_answersTheNewCodes() throws Exception {
        final var account = new CurrentAccount(UUID.randomUUID(), "alice");
        when(currentAccountResolver.resolve()).thenReturn(account);
        when(generateRecoveryCodesUseCase.execute(account.id())).thenReturn(List.of("AAAA", "BBBB"));

        MockMvcBuilders.standaloneSetup(controller).build().perform(post("/api/account/recovery-codes"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.recoveryCodes[1]").value("BBBB"))
                .andExpect(jsonPath("$.remaining").value(2));
    }
}
