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

import com.irurueta.authserver.serviceclient.application.documents.ListDocumentsOnBehalfOfUseCase;
import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.ServiceTokens;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tools.jackson.databind.json.JsonMapper;

/**
 * Command-line client of the OAuth 2.0 token exchange grant (RFC 8693): exchanges the access token of a user, read
 * from the {@code SERVICE_CLIENT_SUBJECT_TOKEN} environment variable, for one that names the user as subject and this
 * client as actor, lists the documents the resource server shows that user and prints each one as a JSON line.
 * <p>
 * <b>Running it from the packaged jar</b>:
 * <pre>
 * SERVICE_CLIENT_SUBJECT_TOKEN=... java -jar service-client-boot.jar --spring.profiles.active=token-exchange
 * </pre>
 * with the same client settings as {@link ClientCredentialsCli}. With {@code
 * --service-client.cli.print-access-token=true} a last {@code Access token: ...} line prints the exchanged token. On
 * any failure the process ends with a non-zero exit code.
 * <p>
 * <b>Why it lives in {@code src/main}</b>: the end-to-end test runs the packaged service-client jar, so the runner
 * has to be in it; it is a genuine, reusable tool of the application and not a test double.
 */
@Component
@Profile(TokenExchangeCli.PROFILE)
@RequiredArgsConstructor
public class TokenExchangeCli implements CommandLineRunner {

    /** Name of the Spring profile that turns the runner on. */
    public static final String PROFILE = "token-exchange";

    /** Lists the documents of a user. */
    private final ListDocumentsOnBehalfOfUseCase listDocumentsOnBehalfOfUseCase;

    /** Gives the exchanged token. */
    private final ServiceTokens serviceTokens;

    /** Writes the lines. */
    private final CliOutput output;

    /** Writes a document as JSON. */
    private final JsonMapper jsonMapper;

    /** The settings. */
    private final CliProperties properties;

    /**
     * Exchanges the token, lists the documents and, when asked, prints the exchanged token.
     *
     * @param args ignored: settings arrive as Spring properties.
     * @throws IllegalStateException if there is no subject token.
     * @throws com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException if the exchange is
     *         refused or the resource server refuses the call.
     */
    @Override
    public void run(final String... args) {
        final var subjectToken = properties.subjectToken();
        if (!StringUtils.hasText(subjectToken)) {
            throw new IllegalStateException(
                    "The access token of the user is required: set SERVICE_CLIENT_SUBJECT_TOKEN");
        }
        listDocumentsOnBehalfOfUseCase.execute(subjectToken)
                .forEach(document -> output.line(jsonMapper.writeValueAsString(document)));
        if (properties.printAccessToken()) {
            output.line("Access token: " + serviceTokens.exchangedToken(subjectToken));
        }
    }
}
