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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Applies {@link OttRateLimiter} to the one-time token endpoints, which are Spring Security filters (so no controller
 * advice sees their failures): {@code POST /ott/generate} counts as a token request and {@code POST /login/ott} and
 * {@code POST /login/second-factor/ott} as submissions, each per client address and per identifier. A request over a
 * limit is answered {@code 429} as {@code application/problem+json} with a {@code Retry-After} header, before any token
 * is stored or any code is checked. The identifier is the one the request names (the {@code username} field of a
 * sign-in, the signed-in user for a second factor, the identifier the session requested a code for for a submission),
 * whether or not it belongs to an account.
 */
public class OttRateLimitFilter extends OncePerRequestFilter {

    /** Path of the token requests, Spring Security's default. */
    public static final String GENERATE_PATH = "/ott/generate";

    /** Type of the problem answered. */
    static final String PROBLEM_TYPE = "urn:problem:ott:rate-limited";

    /** The limiter. */
    private final OttRateLimiter limiter;

    /** Matches the token requests. */
    private final RequestMatcher generateMatcher = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, GENERATE_PATH);

    /** Matches the submissions. */
    private final RequestMatcher verificationMatcher = request -> HttpMethod.POST.matches(request.getMethod())
            && (matches(request, OneTimeTokenPageApi.PATH_OTT_CODE_PAGE)
            || matches(request, OttSecondFactorFilter.SECOND_FACTOR_OTT_PATH));

    /**
     * Creates the filter.
     *
     * @param limiter the limiter.
     */
    public OttRateLimitFilter(final OttRateLimiter limiter) {
        this.limiter = limiter;
    }

    /**
     * Counts the request and answers {@code 429} when it is over a limit.
     *
     * @param request     the request.
     * @param response    the response.
     * @param filterChain the rest of the chain.
     * @throws ServletException if the chain fails.
     * @throws IOException      if the answer cannot be written.
     */
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response,
            final FilterChain filterChain) throws ServletException, IOException {
        try {
            if (generateMatcher.matches(request)) {
                limiter.checkGeneration(request.getRemoteAddr(), generationIdentifier(request));
            } else if (verificationMatcher.matches(request)) {
                limiter.checkVerification(request.getRemoteAddr(), verificationIdentifier(request));
            }
        } catch (final OttRateLimitExceededException e) {
            tooManyRequests(response, e);
            return;
        }
        filterChain.doFilter(request, response);
    }

    /**
     * Gets the identifier a token request names.
     *
     * @param request the request.
     * @return the signed-in user for a second factor, the {@code username} field otherwise; {@code null} when none.
     */
    private static String generationIdentifier(final HttpServletRequest request) {
        final var current = SecurityContextHolder.getContext().getAuthentication();
        final var parameters = OttGenerationParameters.from(request, current);
        final var identifier = parameters.purpose() == OttPurpose.SECOND_FACTOR ? current.getName()
                : request.getParameter(OttGenerationParameters.USERNAME_PARAMETER);
        final var cleaned = LinkTokenUsername.clean(identifier);
        return StringUtils.hasText(cleaned) ? cleaned.toLowerCase(Locale.ROOT) : null;
    }

    /**
     * Gets the identifier a submission is for.
     *
     * @param request the request.
     * @return the identifier the session requested a token for, else the signed-in user; {@code null} when none (a
     *         magic link carries no identifier).
     */
    private static String verificationIdentifier(final HttpServletRequest request) {
        return PendingOtt.of(request).map(PendingOtt::identifier).orElseGet(() -> {
            final var current = SecurityContextHolder.getContext().getAuthentication();
            return OttGenerationParameters.isSignedIn(current) ? current.getName() : null;
        });
    }

    /**
     * Tells whether a request is for a path.
     *
     * @param request the request.
     * @param path    the path.
     * @return {@code true} when the path of the request, without the context path, is the given one.
     */
    private static boolean matches(final HttpServletRequest request, final String path) {
        return PathPatternRequestMatcher.withDefaults().matcher(path).matches(request);
    }

    /**
     * Answers {@code 429} with a problem body that carries no user data.
     *
     * @param response  the response.
     * @param exception the limit that was exceeded.
     * @throws IOException if the answer cannot be written.
     */
    private static void tooManyRequests(final HttpServletResponse response,
            final OttRateLimitExceededException exception) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader(HttpHeaders.RETRY_AFTER, Long.toString(Math.max(1, exception.getRetryAfter().toSeconds())));
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"type\":\"" + PROBLEM_TYPE + "\",\"title\":\"Too many requests\",\"status\":"
                + HttpStatus.TOO_MANY_REQUESTS.value() + ",\"detail\":\"Too many requests; try again later\"}");
    }
}
