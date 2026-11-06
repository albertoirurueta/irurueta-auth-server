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

import com.irurueta.authserver.authorization.api.web.consent.ConsentPageModel.ScopeView;
import java.util.Arrays;
import java.util.Collection;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.context.MessageSource;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Builds the {@link ConsentPageModel} from the registered client, the requested scopes and the scopes granted
 * earlier. Scope descriptions come from {@code messages.properties} ({@code consent.scope.<name>}); a scope without
 * a description is shown by its name.
 */
@Component
@RequiredArgsConstructor
public class ConsentPageModelMapper {

    /** Prefix of the message code of a scope description. */
    static final String SCOPE_MESSAGE_PREFIX = "consent.scope.";

    /** Resolves the scope descriptions. */
    private final MessageSource messageSource;

    /**
     * Maps the consent request to its view model. The {@code openid} scope is never listed: it only asks for the
     * identity the user has just proved by signing in. Scopes granted earlier are listed apart.
     *
     * @param client          client that asks for access.
     * @param principalName   name of the signed-in user.
     * @param state           state of the authorization request.
     * @param requestedScopes requested scopes, space delimited as in the authorization request.
     * @param grantedScopes   scopes the user granted to the client earlier.
     * @param locale          locale of the descriptions.
     * @return the view model.
     */
    public ConsentPageModel toModel(
            final RegisteredClient client, final String principalName, final String state,
            final String requestedScopes, final Collection<String> grantedScopes, final Locale locale) {
        final var toApprove = Arrays.stream(StringUtils.delimitedListToStringArray(requestedScopes, " "))
                .filter(StringUtils::hasText)
                .filter(scope -> !OidcScopes.OPENID.equals(scope))
                .filter(scope -> !grantedScopes.contains(scope))
                .distinct()
                .map(scope -> view(scope, locale))
                .toList();
        final var approved = grantedScopes.stream()
                .filter(scope -> !OidcScopes.OPENID.equals(scope))
                .sorted()
                .map(scope -> view(scope, locale))
                .toList();
        return new ConsentPageModel(client.getClientId(), client.getClientName(), principalName, state, toApprove,
                approved);
    }

    /**
     * Describes a scope.
     *
     * @param scope  name of the scope.
     * @param locale locale of the description.
     * @return the scope with its description.
     */
    private ScopeView view(final String scope, final Locale locale) {
        return new ScopeView(scope, messageSource.getMessage(SCOPE_MESSAGE_PREFIX + scope, null, scope, locale));
    }
}
