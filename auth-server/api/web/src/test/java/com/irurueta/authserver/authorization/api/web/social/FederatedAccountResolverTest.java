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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.social.FederatedLogin;
import com.irurueta.authserver.authorization.application.social.FederatedLoginOutcome;
import com.irurueta.authserver.authorization.application.social.ResolveFederatedLoginUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.FederatedLoginRefusedException;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

/**
 * Unit tests of {@link FederatedAccountResolver}.
 */
@ExtendWith(MockitoExtension.class)
class FederatedAccountResolverTest {

    /** Username of the account. */
    private static final String USERNAME = "alice";

    /** Subject of the provider. */
    private static final String SUBJECT = "subject";

    /** E-mail address of the account. */
    private static final String EMAIL = "alice@example.org";

    /** Finds, links or provisions the account. */
    @Mock
    private ResolveFederatedLoginUseCase resolveFederatedLoginUseCase;

    /** Loads the account, refusing one that may not sign in. */
    @Mock
    private UserDetailsService accountStatusUserDetailsService;

    /** Resolver under test. */
    @InjectMocks
    private FederatedAccountResolver resolver;

    /**
     * Verifies that the account of the resolved login is loaded through the status-checking service.
     */
    @Test
    void resolve_whenAccountMaySignIn_returnsItsDetails() {
        final var details = User.withUsername(USERNAME).password("hash").authorities("ROLE_USER").build();
        when(resolveFederatedLoginUseCase.execute(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true))
                .thenReturn(login());
        when(accountStatusUserDetailsService.loadUserByUsername(USERNAME)).thenReturn(details);

        assertSame(details, resolver.resolve(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true));
    }

    /**
     * Verifies that a linked account that is disabled is refused with the same {@code access_denied} error as any other
     * refusal, whatever the reason.
     */
    @Test
    void resolve_whenAccountIsDisabled_throwsAccessDenied() {
        when(resolveFederatedLoginUseCase.execute(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true))
                .thenReturn(login());
        when(accountStatusUserDetailsService.loadUserByUsername(USERNAME))
                .thenThrow(new DisabledException("disabled"));

        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> resolver.resolve(IdentityProvider.GOOGLE, SUBJECT, EMAIL, true));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, error.getError().getErrorCode());
        assertEquals(FederatedAccountResolver.REFUSED, error.getError().getDescription());
        assertInstanceOf(DisabledException.class, error.getCause());
    }

    /**
     * Verifies that a refusal of the use case (an unverified address) is the same {@code access_denied} error.
     */
    @Test
    void resolve_whenLoginIsRefused_throwsAccessDenied() {
        when(resolveFederatedLoginUseCase.execute(IdentityProvider.GITHUB, SUBJECT, null, false))
                .thenThrow(new FederatedLoginRefusedException("no verified e-mail"));

        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> resolver.resolve(IdentityProvider.GITHUB, SUBJECT, null, false));

        assertEquals(OAuth2ErrorCodes.ACCESS_DENIED, error.getError().getErrorCode());
    }

    /**
     * Builds the result of the use case.
     *
     * @return the login.
     */
    private static FederatedLogin login() {
        final var id = UUID.randomUUID();
        final var account = new UserAccount(id, USERNAME, "hash", true, List.of("ROLE_USER"), EMAIL, true,
                UserAccount.DEFAULT_TENANT);
        final var identity = new FederatedIdentity(UUID.randomUUID(), id, IdentityProvider.GOOGLE, SUBJECT, EMAIL,
                Instant.EPOCH, null);
        return new FederatedLogin(account, identity, FederatedLoginOutcome.EXISTING);
    }
}
