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

import com.irurueta.authserver.authorization.api.web.mfa.CurrentAccountResolver;
import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.IdentitiesPageApi;
import com.irurueta.authserver.authorization.application.social.ListIdentitiesUseCase;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;

// tag::social-identities-page-controller[]
/**
 * Serves the account page of the linked identities and the form post that starts linking another one, as the contract
 * {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes them through the generated
 * {@link IdentitiesPageApi}. The post records the link marker ({@link PendingIdentityLinks}) and redirects to the
 * provider's sign-in; the provider's answer then links the identity to the signed-in account (see
 * {@link FederatedAccountResolver}). The page exists whether or not a provider is configured; without one it lists the
 * linked identities only. The chain keeps both behind the multi-factor policy ({@link IdentitiesPageChainCustomizer}).
 */
@Controller
@RequiredArgsConstructor
public class IdentitiesPageController implements IdentitiesPageApi {

    /** Name of the template of the page. */
    static final String VIEW_NAME = "account-identities";

    /** Name of the model attribute that holds the linked identities. */
    static final String IDENTITIES_ATTRIBUTE = "identities";

    /** Name of the model attribute that holds the providers that can be linked. */
    static final String PROVIDERS_ATTRIBUTE = "providers";

    /** Name of the model attribute that holds the outcome of the previous link. */
    static final String STATUS_ATTRIBUTE = "status";

    /** Status of an identity that was linked. */
    static final String LINKED = "linked";

    /** Status of an identity that belongs to another account. */
    static final String ALREADY_LINKED = "already-linked";

    /** Status of a provider that is not configured. */
    static final String UNKNOWN_PROVIDER = "unknown-provider";

    /** Path that starts the sign-in with a provider, answered by Spring Security. */
    static final String AUTHORIZATION_PATH = "/oauth2/authorization/";

    /** The statuses the page tells; any other value of the parameter is ignored. */
    private static final Set<String> STATUSES = Set.of(LINKED, ALREADY_LINKED, UNKNOWN_PROVIDER);

    /** Resolves the account of the request. */
    private final CurrentAccountResolver currentAccountResolver;

    /** Lists the identities of an account. */
    private final ListIdentitiesUseCase listIdentitiesUseCase;

    /** Maps the identities onto the view model. */
    private final IdentityViewMapper identityViewMapper;

    /** Keeps the link markers. */
    private final PendingIdentityLinks pendingIdentityLinks;

    /** Registrations of the configured providers; absent while none is configured. */
    private final ObjectProvider<ClientRegistrationRepository> clientRegistrations;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /** The current request, injected as a thread-bound proxy, which holds the session. */
    private final HttpServletRequest request;

    /**
     * Renders the page.
     *
     * @param status outcome of the previous link, ignored when it is not one of the known ones.
     * @return the page, never cached.
     */
    @Override
    public ResponseEntity<String> identitiesPage(final String status) {
        final var account = currentAccountResolver.resolve();
        final var model = new HashMap<String, Object>();
        model.put(IDENTITIES_ATTRIBUTE, identityViewMapper.toViews(listIdentitiesUseCase.execute(account.id())));
        model.put(PROVIDERS_ATTRIBUTE, configuredProviders().stream().map(IdentityProvider::id).toList());
        if (status != null && STATUSES.contains(status)) {
            model.put(STATUS_ATTRIBUTE, status);
        }
        final var page = pageRenderer.render(VIEW_NAME, model);
        return ResponseEntity.status(page.getStatusCode())
                .headers(page.getHeaders())
                .cacheControl(CacheControl.noStore())
                .body(page.getBody());
    }

    /**
     * Records the link marker and sends the browser to the provider's sign-in.
     *
     * @param provider registration id of the provider.
     * @return a redirect to the provider's sign-in, or to the page with {@code unknown-provider}.
     */
    @Override
    public ResponseEntity<Void> linkIdentityPage(final String provider) {
        final var account = currentAccountResolver.resolve();
        final var configured = IdentityProvider.fromId(provider).filter(configuredProviders()::contains);
        if (configured.isEmpty()) {
            return redirect(PATH_IDENTITIES_PAGE + "?" + STATUS_ATTRIBUTE + "=" + UNKNOWN_PROVIDER);
        }
        pendingIdentityLinks.begin(request.getSession(), configured.get(), account.id(), account.username());
        return redirect(AUTHORIZATION_PATH + configured.get().id());
    }

    /**
     * Lists the providers that are configured, in the order of {@link IdentityProvider}.
     *
     * @return the configured providers, possibly none.
     */
    private List<IdentityProvider> configuredProviders() {
        return Optional.ofNullable(clientRegistrations.getIfAvailable())
                .map(repository -> Arrays.stream(IdentityProvider.values())
                        .filter(candidate -> repository.findByRegistrationId(candidate.id()) != null)
                        .toList())
                .orElseGet(List::of);
    }

    /**
     * Answers a redirect that the browser follows with a GET.
     *
     * @param location the target, relative to the application.
     * @return the redirect.
     */
    private ResponseEntity<Void> redirect(final String location) {
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .header(HttpHeaders.LOCATION, request.getContextPath() + location)
                .build();
    }
}
// end::social-identities-page-controller[]
