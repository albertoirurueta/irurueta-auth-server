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
package com.irurueta.authserver.authorization;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.json.JsonMapper;

/**
 * Stands in for the external identity providers of the social login tests: one in-process WireMock server answers the
 * authorization-code exchange, the key set, the user information and (for GitHub) the e-mail addresses of every
 * provider, each under its own path. The application keeps its own registrations (so the issuers, scopes, validators
 * and the Apple client secret are the real ones) and only has the endpoint addresses pointed at this server by
 * {@link FakeIdentityProvidersConfiguration}. The signing key of the ID tokens is generated when the class loads and
 * never leaves the process; nothing is committed and nothing reaches the network. This is test data standing in for
 * somebody else's service, not a double of one of this repository's ports.
 */
final class FakeIdentityProviders {

    /** Length in bits of the signing key of the ID tokens. */
    private static final int KEY_BITS = 2048;

    /** How long an ID token stays valid. */
    private static final Duration TOKEN_LIFETIME = Duration.ofMinutes(5);

    /** Lifetime in seconds an access token reports. */
    private static final int ACCESS_TOKEN_SECONDS = 3600;

    /** Content type of the answers. */
    private static final String JSON = "application/json";

    /** Name of the content type header. */
    private static final String CONTENT_TYPE = "Content-Type";

    /** Path suffix of the authorization endpoint of a provider. */
    private static final String AUTHORIZE = "/authorize";

    /** Path suffix of the token endpoint of a provider. */
    private static final String TOKEN = "/token";

    /** Path suffix of the key set endpoint of a provider. */
    private static final String JWKS = "/jwks";

    /** Path suffix of the user information endpoint of a provider. */
    private static final String USER_INFO = "/userinfo";

    /** Path of the GitHub user endpoint. */
    private static final String GITHUB_USER = "/github/user";

    /** Registration id of GitHub. */
    private static final String GITHUB = "github";

    /** Claim that carries the subject. */
    private static final String SUB = "sub";

    /** Mapper of the answers. */
    private static final JsonMapper MAPPER = JsonMapper.builder().build();

    /** Signing key of the ID tokens, generated for the run. */
    private static final RSAKey KEY = generateKey();

    /** The fake providers' server. */
    private static final WireMockServer SERVER = start();

    /** Not instantiable. */
    private FakeIdentityProviders() {
    }

    /**
     * Gives the address of the server.
     *
     * @return its base URL, without a trailing slash.
     */
    static String baseUrl() {
        return SERVER.baseUrl();
    }

    /**
     * Forgets every stub and request, and publishes the key set again.
     */
    static void reset() {
        SERVER.resetAll();
        final var keys = new JWKSet(KEY.toPublicJWK()).toString();
        for (final var provider : List.of("google", "microsoft", "apple")) {
            SERVER.stubFor(get(urlPathEqualTo("/" + provider + JWKS))
                    .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON).withBody(keys)));
        }
    }

    /**
     * Points the endpoints of a registration at the fake server.
     *
     * @param registration the real registration.
     * @return the same registration with the endpoints of the fake provider.
     */
    static ClientRegistration redirect(final ClientRegistration registration) {
        final var id = registration.getRegistrationId();
        final var details = registration.getProviderDetails();
        final var builder = ClientRegistration.withClientRegistration(registration)
                .authorizationUri(baseUrl() + "/" + id + AUTHORIZE)
                .tokenUri(baseUrl() + "/" + id + TOKEN);
        if (StringUtils.hasText(details.getJwkSetUri())) {
            builder.jwkSetUri(baseUrl() + "/" + id + JWKS);
        }
        if (StringUtils.hasText(details.getUserInfoEndpoint().getUri())) {
            builder.userInfoUri(GITHUB.equals(id) ? baseUrl() + GITHUB_USER : baseUrl() + "/" + id + USER_INFO);
        }
        return builder.build();
    }

    /**
     * Signs an ID token.
     *
     * @param issuer   the {@code iss} claim.
     * @param audience the client id the token is for.
     * @param nonce    the nonce of the authorization request.
     * @param claims   the other claims, among them {@code sub}.
     * @return the compact serialization of the token.
     */
    static String idToken(final String issuer, final String audience, final String nonce,
                          final Map<String, Object> claims) {
        final var now = Instant.now();
        final var builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(TOKEN_LIFETIME)))
                .claim("nonce", nonce);
        claims.forEach(builder::claim);
        final var jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY.getKeyID()).build(), builder.build());
        try {
            jwt.sign(new RSASSASigner(KEY));
        } catch (final JOSEException e) {
            throw new IllegalStateException("The test ID token cannot be signed", e);
        }
        return jwt.serialize();
    }

    /**
     * Makes an OpenID Connect provider answer the code exchange with an ID token and the user information request
     * with the claims of the user.
     *
     * @param provider registration id of the provider.
     * @param idToken  the ID token the token endpoint hands out.
     * @param userInfo what the user information endpoint answers.
     */
    static void stubOidc(final String provider, final String idToken, final Map<String, Object> userInfo) {
        final var token = new LinkedHashMap<String, Object>();
        token.put("access_token", "access-" + UUID.randomUUID());
        token.put("token_type", "Bearer");
        token.put("expires_in", ACCESS_TOKEN_SECONDS);
        token.put("scope", "openid profile email");
        token.put("id_token", idToken);
        SERVER.stubFor(post(urlPathEqualTo("/" + provider + TOKEN))
                .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON).withBody(MAPPER.writeValueAsString(token))));
        SERVER.stubFor(get(urlPathEqualTo("/" + provider + USER_INFO))
                .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON)
                        .withBody(MAPPER.writeValueAsString(userInfo))));
    }

    /**
     * Makes GitHub answer the code exchange, the user request and the request for the e-mail addresses.
     *
     * @param accessToken the access token the exchange hands out.
     * @param id          the numeric id of the user.
     * @param emails      what {@code /user/emails} answers.
     */
    static void stubGitHub(final String accessToken, final long id, final List<Map<String, Object>> emails) {
        final var token = Map.of("access_token", accessToken, "token_type", "bearer", "scope", "read:user,user:email");
        SERVER.stubFor(post(urlPathEqualTo("/" + GITHUB + TOKEN))
                .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON).withBody(MAPPER.writeValueAsString(token))));
        final var user = Map.of("id", id, "login", "octo-" + id, "name", "Octo Cat");
        SERVER.stubFor(get(urlPathEqualTo(GITHUB_USER))
                .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON).withBody(MAPPER.writeValueAsString(user))));
        SERVER.stubFor(get(urlPathEqualTo(GITHUB_USER + "/emails"))
                .willReturn(aResponse().withHeader(CONTENT_TYPE, JSON).withBody(MAPPER.writeValueAsString(emails))));
    }

    /**
     * Reads what the application sent to the token endpoint of a provider.
     *
     * @param provider registration id of the provider.
     * @return the form parameters of every request, oldest first.
     */
    static List<Map<String, String>> tokenRequests(final String provider) {
        return SERVER.findAll(postRequestedFor(urlPathEqualTo("/" + provider + TOKEN))).stream()
                .map(request -> {
                    final var parameters = new LinkedHashMap<String, String>();
                    UriComponentsBuilder.newInstance().query(request.getBodyAsString()).build().getQueryParams()
                            .forEach((name, values) -> parameters.put(name, values.getFirst()));
                    return (Map<String, String>) parameters;
                })
                .toList();
    }

    /**
     * Builds the claims of an OpenID Connect user.
     *
     * @param subject       subject at the provider.
     * @param email         e-mail address, may be {@code null}.
     * @param emailVerified whether the provider verified the address.
     * @return the claims.
     */
    static Map<String, Object> userClaims(final String subject, final String email, final boolean emailVerified) {
        final var claims = new LinkedHashMap<String, Object>();
        claims.put(SUB, subject);
        if (email != null) {
            claims.put("email", email);
            claims.put("email_verified", emailVerified);
        }
        claims.put("name", "Test User");
        return claims;
    }

    /**
     * Generates the signing key.
     *
     * @return the key.
     */
    private static RSAKey generateKey() {
        try {
            return new RSAKeyGenerator(KEY_BITS).keyID(UUID.randomUUID().toString()).generate();
        } catch (final JOSEException e) {
            throw new IllegalStateException("The test key cannot be generated", e);
        }
    }

    /**
     * Starts the server on a free port.
     *
     * @return the running server.
     */
    private static WireMockServer start() {
        final var server = new WireMockServer(WireMockConfiguration.options().dynamicPort());
        server.start();
        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));
        return server;
    }
}
