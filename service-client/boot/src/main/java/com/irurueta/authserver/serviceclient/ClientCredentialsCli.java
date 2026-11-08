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


package com.irurueta.authserver.serviceclient;

import com.irurueta.authserver.serviceclient.application.documents.ListDocumentsUseCase;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.ServiceTokens;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/**
 * Command-line client of the OAuth 2.0 client credentials grant: obtains an access token with its own credentials,
 * lists the documents the resource server shows it and prints each one as a JSON line.
 * <p>
 * <b>Running it from the packaged jar</b>:
 * <pre>
 * java -jar service-client-boot.jar --spring.profiles.active=client-credentials \
 *     --service-client.auth.token-uri=http://localhost:9000/oauth2/token \
 *     --service-client.resource-server.base-uri=http://localhost:8081
 * </pre>
 * with {@code SERVICE_CLIENT_ID} and {@code SERVICE_CLIENT_SECRET} (or {@code --service-client.auth.method} and its
 * key or SSL bundle for the other authentication methods, see {@code application-client-credentials.yml}). With
 * {@code --service-client.cli.print-access-token=true} a last {@code Access token: ...} line prints the token. On any
 * failure the process ends with a non-zero exit code.
 * <p>
 * <b>Why it lives in {@code src/main}</b>: the end-to-end test runs the packaged service-client jar, so the runner
 * has to be in it; it is a genuine, reusable tool of the application and not a test double.
 */
@Component
@Profile(ClientCredentialsCli.PROFILE)
@RequiredArgsConstructor
public class ClientCredentialsCli implements CommandLineRunner {

    /** Name of the Spring profile that turns the runner on. */
    public static final String PROFILE = "client-credentials";

    /** Lists the documents. */
    private final ListDocumentsUseCase listDocumentsUseCase;

    /** Gives the token the call used. */
    private final ServiceTokens serviceTokens;

    /** Writes the lines. */
    private final CliOutput output;

    /** Writes a document as JSON. */
    private final JsonMapper jsonMapper;

    /** The settings. */
    private final CliProperties properties;

    /**
     * Lists the documents and, when asked, prints the token.
     *
     * @param args ignored: settings arrive as Spring properties.
     * @throws com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException if the token cannot be
     *         obtained or the resource server refuses the call.
     */
    @Override
    public void run(final String... args) {
        listDocumentsUseCase.execute().forEach(document -> output.line(jsonMapper.writeValueAsString(document)));
        if (properties.printAccessToken()) {
            output.line("Access token: " + serviceTokens.clientCredentialsToken());
        }
    }
}
