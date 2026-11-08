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
package com.irurueta.authserver.e2e;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

/**
 * Registers clients in a running {@code auth-server} through its admin API ({@code POST /api/admin/clients}), the way
 * an
 * operator would. The API needs a token with the {@code admin} scope, and the only clients a fresh {@code dev} server
 * has are the seeded ones, so one confidential admin client is inserted by SQL as a copy of the seeded {@code bff}
 * client (it shares its secret) limited to the {@code client_credentials} grant and the {@code admin} scope.
 */
final class ClientAdminApi {

    /** Scope that lets a client read documents. */
    static final String DOCUMENTS_READ = "documents.read";

    /** Audience of the resource server. */
    static final String RESOURCE_SERVER_AUDIENCE = "resource-server";

    /** Identifier of the administration client. */
    private static final String ADMIN_CLIENT_ID = "e2e-admin";

    /** Scope that opens the admin API. */
    private static final String ADMIN_SCOPE = "admin";

    /** Seeded client the administration client is copied from. */
    private static final String SEEDED_CLIENT = "bff";

    /** HTTP status of a created resource. */
    private static final int HTTP_CREATED = 201;

    /** HTTP status of a successful response. */
    private static final int HTTP_OK = 200;

    /** Lifetime of the access tokens of the clients that are created. */
    private static final String ACCESS_TOKEN_TTL = "PT10M";

    /** Lifetime of the refresh tokens of the clients that are created. */
    private static final String REFRESH_TOKEN_TTL = "PT1H";

    /** Mapper of the JSON of the API. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** The server whose clients are administered. */
    private final RunningAuthServer authServer;

    /** Access token with the admin scope. */
    private final String adminToken;

    /**
     * Creates the administration client of the server and obtains its token.
     *
     * @param authServer the running server.
     * @throws Exception if the client cannot be inserted or the token cannot be obtained.
     */
    ClientAdminApi(final RunningAuthServer authServer) throws Exception {
        this.authServer = authServer;
        authServer.sql("INSERT INTO oauth2_registered_client (id, client_id, client_secret, client_name, "
                + "client_authentication_methods, authorization_grant_types, redirect_uris, scopes, "
                + "client_settings, token_settings) SELECT gen_random_uuid()::text, '" + ADMIN_CLIENT_ID
                + "', client_secret, client_name, client_authentication_methods, 'client_credentials', '', '"
                + ADMIN_SCOPE + "', client_settings, token_settings FROM oauth2_registered_client "
                + "WHERE client_id = '" + SEEDED_CLIENT + "'");
        final var credentials = Base64.getEncoder().encodeToString(
                (ADMIN_CLIENT_ID + ":" + authServer.clientSecret()).getBytes(StandardCharsets.UTF_8));
        final var request = HttpRequest.newBuilder(URI.create(authServer.issuer() + "/oauth2/token"))
                .header("Authorization", "Basic " + credentials)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials&scope="
                        + URLEncoder.encode(ADMIN_SCOPE, StandardCharsets.UTF_8)))
                .build();
        final var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(HTTP_OK, response.statusCode(), "token of the admin client: " + response.body());
        adminToken = JSON.readTree(response.body()).get("access_token").asString();
    }

    /**
     * Starts the definition of a confidential client that reads documents for the resource server, with the
     * given authentication methods and grant types; the caller adds what the methods need.
     *
     * @param clientId    identifier of the client.
     * @param authMethods client authentication methods.
     * @param grantTypes  grant types.
     * @return the definition, ready to be completed and passed to {@link #create(ObjectNode)}.
     */
    static ObjectNode confidentialClient(final String clientId, final List<String> authMethods,
                                         final List<String> grantTypes) {
        final var definition = JSON.createObjectNode();
        definition.put("clientId", clientId);
        definition.put("name", clientId);
        definition.put("confidential", true);
        final var methods = definition.putArray("authMethods");
        authMethods.forEach(methods::add);
        final var grants = definition.putArray("grantTypes");
        grantTypes.forEach(grants::add);
        definition.putArray("redirectUris");
        definition.putArray("scopes").add(DOCUMENTS_READ);
        definition.putArray("audiences").add(RESOURCE_SERVER_AUDIENCE);
        definition.put("accessTokenTtl", ACCESS_TOKEN_TTL);
        definition.put("refreshTokenTtl", REFRESH_TOKEN_TTL);
        return definition;
    }

    /**
     * Creates a client.
     *
     * @param definition the client definition, as the admin API's {@code ClientRequest}.
     * @return the generated secret of the client, or {@code null} when it has none.
     * @throws Exception if the request fails or the server refuses the definition.
     */
    String create(final ObjectNode definition) throws Exception {
        final var request = HttpRequest.newBuilder(URI.create(authServer.issuer() + "/api/admin/clients"))
                .header("Authorization", "Bearer " + adminToken)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(definition)))
                .build();
        final var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
        assertEquals(HTTP_CREATED, response.statusCode(), response.body());
        final JsonNode secret = JSON.readTree(response.body()).get("clientSecret");
        return secret == null || secret.isNull() ? null : secret.asString();
    }
}
