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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccount;
import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.application.social.ListIdentitiesUseCase;
import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/** Unit tests of {@link IdentitiesPageController}. */
@ExtendWith(MockitoExtension.class)
class IdentitiesPageControllerTest {

    /** Name of the signed-in account. */
    private static final String USERNAME = "alice";

    /** Account of the requests. */
    private final CurrentAccount account = new CurrentAccount(UUID.randomUUID(), USERNAME);

    /** Resolves the account of the request. */
    @Mock
    private CurrentAccountResolver currentAccountResolver;

    /** Lists the identities. */
    @Mock
    private ListIdentitiesUseCase listIdentitiesUseCase;

    /** Real mapper. */
    @Spy
    private IdentityViewMapper identityViewMapper = new IdentityViewMapper();

    /** Keeps the link markers. */
    @Mock
    private PendingIdentityLinks pendingIdentityLinks;

    /** Provider of the registrations of the configured providers. */
    @Mock
    private ObjectProvider<ClientRegistrationRepository> clientRegistrations;

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** The request. */
    @Mock
    private HttpServletRequest request;

    /** Controller under test. */
    @InjectMocks
    private IdentitiesPageController controller;

    /**
     * Resolves the account of every request.
     */
    @BeforeEach
    void setUp() {
        when(currentAccountResolver.resolve()).thenReturn(account);
    }

    /**
     * The page lists the linked identities and the configured providers, tells a known status and is never cached.
     */
    @Test
    @SuppressWarnings("unchecked")
    void identitiesPage_whenProvidersAreConfigured_rendersTheIdentitiesAndTheProviders() {
        givenProviders(IdentityProvider.GOOGLE, IdentityProvider.GITHUB);
        when(listIdentitiesUseCase.execute(account.id())).thenReturn(List.of(new FederatedIdentity(UUID.randomUUID(),
                account.id(), IdentityProvider.GOOGLE, "subject", null, Instant.EPOCH, null)));
        when(pageRenderer.render(eq(IdentitiesPageController.VIEW_NAME), anyMap()))
                .thenReturn(ResponseEntity.ok("<html></html>"));

        final var page = controller.identitiesPage(IdentitiesPageController.LINKED);

        final var model = ArgumentCaptor.<Map<String, Object>>captor();
        verify(pageRenderer).render(eq(IdentitiesPageController.VIEW_NAME), model.capture());
        assertEquals(List.of(new IdentityView("google", null, Instant.EPOCH)),
                model.getValue().get(IdentitiesPageController.IDENTITIES_ATTRIBUTE));
        assertEquals(List.of("google", "github"), model.getValue().get(IdentitiesPageController.PROVIDERS_ATTRIBUTE));
        assertEquals(IdentitiesPageController.LINKED, model.getValue().get(IdentitiesPageController.STATUS_ATTRIBUTE));
        assertEquals("no-store", page.getHeaders().getCacheControl());
    }

    /**
     * Without a configured provider the page lists none, and an unknown status is ignored.
     */
    @Test
    @SuppressWarnings("unchecked")
    void identitiesPage_whenNoProviderIsConfigured_rendersNoProviderAndIgnoresAnUnknownStatus() {
        when(clientRegistrations.getIfAvailable()).thenReturn(null);
        when(listIdentitiesUseCase.execute(account.id())).thenReturn(List.of());
        when(pageRenderer.render(eq(IdentitiesPageController.VIEW_NAME), anyMap()))
                .thenReturn(ResponseEntity.ok("<html></html>"));

        controller.identitiesPage("<script>");

        final var model = ArgumentCaptor.<Map<String, Object>>captor();
        verify(pageRenderer).render(eq(IdentitiesPageController.VIEW_NAME), model.capture());
        assertEquals(List.of(), model.getValue().get(IdentitiesPageController.PROVIDERS_ATTRIBUTE));
        assertFalse(model.getValue().containsKey(IdentitiesPageController.STATUS_ATTRIBUTE));
    }

    /**
     * A configured provider records the marker and redirects to the provider's sign-in.
     */
    @Test
    void linkIdentityPage_whenTheProviderIsConfigured_recordsTheMarkerAndRedirectsToTheProvider() {
        givenProviders(IdentityProvider.GOOGLE);
        final var session = mock(HttpSession.class);
        when(request.getSession()).thenReturn(session);
        when(request.getContextPath()).thenReturn("");

        final var response = controller.linkIdentityPage("google");

        assertEquals(HttpStatus.SEE_OTHER, response.getStatusCode());
        assertEquals("/oauth2/authorization/google", response.getHeaders().getFirst(HttpHeaders.LOCATION));
        verify(pendingIdentityLinks).begin(session, IdentityProvider.GOOGLE, account.id(), USERNAME);
    }

    /**
     * A provider that is not configured, or not a provider at all, records nothing.
     */
    @Test
    void linkIdentityPage_whenTheProviderIsNotConfigured_redirectsToThePageWithUnknownProvider() {
        givenProviders(IdentityProvider.GOOGLE);
        when(request.getContextPath()).thenReturn("");

        final var notConfigured = controller.linkIdentityPage("github");
        final var unknown = controller.linkIdentityPage("myspace");

        assertEquals("/account/identities?status=unknown-provider",
                notConfigured.getHeaders().getFirst(HttpHeaders.LOCATION));
        assertEquals("/account/identities?status=unknown-provider",
                unknown.getHeaders().getFirst(HttpHeaders.LOCATION));
        verifyNoInteractions(pendingIdentityLinks);
    }

    /**
     * Configures the given providers.
     *
     * @param providers the configured providers.
     */
    private void givenProviders(final IdentityProvider... providers) {
        final var configured = Arrays.stream(providers).map(IdentityProvider::id).toList();
        final var repository = mock(ClientRegistrationRepository.class);
        when(repository.findByRegistrationId(anyString())).thenAnswer(invocation -> {
            final String id = invocation.getArgument(0);
            return configured.contains(id) ? registration(id) : null;
        });
        when(clientRegistrations.getIfAvailable()).thenReturn(repository);
    }

    /**
     * Builds the registration of a provider.
     *
     * @param id registration id of the provider.
     * @return its registration.
     */
    private static ClientRegistration registration(final String id) {
        return ClientRegistration.withRegistrationId(id).clientId("client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://idp.example/authorize").tokenUri("https://idp.example/token").build();
    }
}
