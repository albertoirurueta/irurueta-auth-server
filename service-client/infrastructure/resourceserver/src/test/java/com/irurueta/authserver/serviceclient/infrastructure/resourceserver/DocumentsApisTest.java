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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Unit tests of {@link DocumentsApis}.
 */
@ExtendWith(MockitoExtension.class)
class DocumentsApisTest {

    /** Registration id. */
    private static final String REGISTRATION_ID = "service-client";

    /** Request factory over the SSL bundle, when there is one. */
    @Mock
    private SslRequestFactories requestFactories;

    /** Interceptors that obtain and send the access token. */
    @Mock
    private ResourceServerInterceptors interceptors;

    /** Principal the token is cached under. */
    @Mock
    private Authentication principal;

    /**
     * Verifies that the client calls the base URI (without a trailing slash) with the interceptors it was given.
     */
    @Test
    void forPrincipal_whenCalled_callsTheBaseUriThroughTheInterceptors() {
        final var builder = RestClient.builder();
        final var server = MockRestServiceServer.bindTo(builder).build();
        final ClientHttpRequestInterceptor tokenSetter = (request, body, execution) -> {
            request.getHeaders().setBearerAuth("the-token");
            return execution.execute(request, body);
        };
        when(requestFactories.create()).thenReturn(Optional.empty());
        when(interceptors.create(REGISTRATION_ID, principal)).thenReturn(List.of(tokenSetter));
        server.expect(requestTo("https://rs.example.com/api/documents"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer the-token"))
                .andRespond(withSuccess("[{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"T\"}]",
                        MediaType.APPLICATION_JSON));
        final var apis = new DocumentsApis(builder,
                new ResourceServerProperties(URI.create("https://rs.example.com/")), requestFactories, interceptors);

        final var documents = apis.forPrincipal(REGISTRATION_ID, principal).listDocuments();

        assertEquals(1, documents.size());
        assertEquals("alice", documents.getFirst().getOwner());
        server.verify();
    }
}
