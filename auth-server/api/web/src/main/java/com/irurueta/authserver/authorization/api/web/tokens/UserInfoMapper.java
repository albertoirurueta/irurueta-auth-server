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

package com.irurueta.authserver.authorization.api.web.tokens;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import java.util.HashMap;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.stereotype.Component;

// tag::tokens-userinfo[]
/**
 * Builds the OpenID Connect UserInfo response from the account of the user, limited to the granted scopes: the
 * {@code sub} claim always; {@code preferred_username}, {@code roles} and {@code tenant} with the {@code profile}
 * scope; {@code email} and {@code email_verified} with the {@code email} scope.
 */
@Component
@RequiredArgsConstructor
public class UserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {

    /** Scope that grants the profile claims. */
    public static final String PROFILE_SCOPE = "profile";

    /** Scope that grants the e-mail claims. */
    public static final String EMAIL_SCOPE = "email";

    /** Finds the account of the user. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    @Override
    public OidcUserInfo apply(final OidcUserInfoAuthenticationContext context) {
        final var username = context.getAuthorization().getPrincipalName();
        final var scopes = context.getAccessToken().getScopes();
        final var claims = new HashMap<String, Object>();
        claims.put(StandardClaimNames.SUB, username);
        findUserAccountUseCase.execute(username).ifPresent(account -> {
            if (scopes.contains(PROFILE_SCOPE)) {
                claims.put(StandardClaimNames.PREFERRED_USERNAME, account.username());
                claims.put(IssuedTokenClaims.ROLES_CLAIM, account.authorities());
                claims.put(IssuedTokenClaims.TENANT_CLAIM, account.tenant());
            }
            if (scopes.contains(EMAIL_SCOPE) && account.email() != null) {
                claims.put(StandardClaimNames.EMAIL, account.email());
                claims.put(StandardClaimNames.EMAIL_VERIFIED, account.emailVerified());
            }
        });
        return new OidcUserInfo(claims);
    }
}
// end::tokens-userinfo[]
