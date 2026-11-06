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
package com.irurueta.authserver.bff.api.web.relay;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

/**
 * Relays the {@code /api/**} calls of the SPA to the resource server, adding the access token of the signed-in user.
 *
 * <p>This endpoint is a hand-mapped pass-through <strong>by design</strong>: it has no operation in the contract
 * {@code apis/bff/rest-server/bff-api-v1.yaml} to generate it from, because it forwards whatever the resource server
 * offers (which is described by the contract of the resource server). It is documented in the contract only as the
 * {@code x-token-relay} extension, and it stays outside the springdoc group ({@code /bff/**}) so the drift test is
 * not affected.
 *
 * <p>Method, path, query, the allowed headers and the body are copied; the response is streamed back unchanged. Neither
 * the browser's cookies nor any token cross it in either direction, and no token is ever logged.
 */
@RestController
@RequiredArgsConstructor
@Slf4j
public class ApiRelayController {

    /** Name of the header that announces a request body of unknown length. */
    private static final String TRANSFER_ENCODING = "Transfer-Encoding";

    /** Client that calls the resource server with the bearer token of the user. */
    private final RestClient relayRestClient;

    /** Where the calls are relayed to. */
    private final RelayProperties properties;

    /** Decides which headers cross the relay. */
    private final RelayHeaderFilter headerFilter;

    // tag::bff-relay-controller[]
    /**
     * Forwards the request to the resource server and writes its answer to the browser.
     *
     * @param request  the request of the browser.
     * @param response the response to the browser.
     * @throws IOException if the response of the resource server cannot be written to the browser.
     */
    @RequestMapping(path = "/api/**", method = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT,
            RequestMethod.PATCH, RequestMethod.DELETE})
    public void relay(final HttpServletRequest request, final HttpServletResponse response) throws IOException {
        final var spec = relayRestClient.method(HttpMethod.valueOf(request.getMethod()))
                .uri(targetUri(request))
                .headers(headers -> headerFilter.copyRequestHeaders(request, headers));
        if (request.getContentLengthLong() > 0 || request.getHeader(TRANSFER_ENCODING) != null) {
            spec.body(out -> request.getInputStream().transferTo(out));
        }
        spec.exchange((upstreamRequest, upstreamResponse) -> {
            response.setStatus(upstreamResponse.getStatusCode().value());
            headerFilter.copyResponseHeaders(upstreamResponse.getHeaders(), response);
            upstreamResponse.getBody().transferTo(response.getOutputStream());
            return null;
        });
    }
    // end::bff-relay-controller[]

    /**
     * Answers 401 when the access token of the user cannot be obtained or renewed, so the SPA signs in again.
     *
     * @param e the failure; only its error code is logged, never a token.
     * @return the 401 response.
     */
    @ExceptionHandler(OAuth2AuthorizationException.class)
    ResponseEntity<ProblemDetail> handleAuthorizationFailure(final OAuth2AuthorizationException e) {
        log.warn("The access token cannot be relayed: {}", e.getError().getErrorCode());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "The session has no valid token"));
    }

    /**
     * Answers 502 when the resource server cannot be reached.
     *
     * @param e the failure.
     * @return the 502 response.
     */
    @ExceptionHandler(ResourceAccessException.class)
    ResponseEntity<ProblemDetail> handleUnreachableTarget(final ResourceAccessException e) {
        log.warn("The resource server cannot be reached: {}", e.getClass().getSimpleName());
        return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                .body(ProblemDetail.forStatusAndDetail(HttpStatus.BAD_GATEWAY, "The resource server is unavailable"));
    }

    /**
     * Builds the URI of the resource server for the request: its base, the path as received and the raw query.
     *
     * @param request the request of the browser.
     * @return the URI to call.
     */
    private URI targetUri(final HttpServletRequest request) {
        final var base = properties.targetUri().toString().replaceFirst("/+$", "");
        final var path = request.getRequestURI().substring(request.getContextPath().length());
        final var query = request.getQueryString();
        try {
            return URI.create(base + path + (query == null ? "" : "?" + query));
        } catch (final IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed request URI", e);
        }
    }
}
