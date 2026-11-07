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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.application.passkeys.ListPasskeysUseCase;
import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;

/**
 * Unit tests of {@link PasskeysPageController}.
 */
@ExtendWith(MockitoExtension.class)
class PasskeysPageControllerTest {

    /** The user. */
    private static final String USERNAME = "alice";

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the passkeys. */
    @Mock
    private ListPasskeysUseCase listPasskeysUseCase;

    /** Real mapper. */
    @Spy
    private PasskeyViewMapper passkeyViewMapper = new PasskeyViewMapper();

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Controller under test. */
    @InjectMocks
    private PasskeysPageController controller;

    /**
     * Verifies that the page is rendered with the passkeys of the signed-in user.
     */
    @Test
    void passkeysPage_whenUserIsSignedIn_rendersThePageWithTheirPasskeys() {
        when(currentAccountResolver.resolve()).thenReturn(new CurrentAccount(UUID.randomUUID(), USERNAME));
        final var created = Instant.parse("2026-01-01T00:00:00Z");
        when(listPasskeysUseCase.execute(USERNAME))
                .thenReturn(List.of(new Passkey("a", "handle", "Laptop", created, null, 0L, false, false)));
        final var page = ResponseEntity.ok("<html></html>");
        when(pageRenderer.render(eq("account-passkeys"), anyMap())).thenReturn(page);

        final var response = controller.passkeysPage();

        assertEquals(page, response);
        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("account-passkeys"), model.capture());
        assertEquals(Map.of("passkeys", List.of(new PasskeyView("Laptop", created, null, false))), model.getValue());
    }

    /**
     * Verifies that the path of the page is the one of the contract.
     */
    @Test
    void passkeysPath_whenRead_isTheContractPath() {
        assertEquals("/account/passkeys", PasskeysPageController.PASSKEYS_PATH);
    }
}
