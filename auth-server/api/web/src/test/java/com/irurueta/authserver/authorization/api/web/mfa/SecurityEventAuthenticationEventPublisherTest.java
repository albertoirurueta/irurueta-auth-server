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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;

/**
 * Unit tests of {@link SecurityEventAuthenticationEventPublisher}.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventAuthenticationEventPublisherTest {

    /** Name of the test user. */
    private static final String USERNAME = "alice";

    /** Password the user presented; it must never be recorded. */
    private static final String SECRET = "s3cret";

    /** Records the events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Subject under test. */
    @InjectMocks
    private SecurityEventAuthenticationEventPublisher publisher;

    /**
     * A user's success is recorded as a login success.
     */
    @Test
    void publishAuthenticationSuccess_whenUserAuthenticates_recordsLoginSuccess() {
        publisher.publishAuthenticationSuccess(UsernamePasswordAuthenticationToken.unauthenticated(USERNAME, SECRET));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.LOGIN_SUCCESS, null, USERNAME, null);
    }

    /**
     * A failure is recorded with the exception type, never its message nor the credentials.
     */
    @Test
    void publishAuthenticationFailure_whenUserFails_recordsLoginFailureWithExceptionType() {
        publisher.publishAuthenticationFailure(new BadCredentialsException("bad " + SECRET),
                UsernamePasswordAuthenticationToken.unauthenticated(USERNAME, SECRET));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.LOGIN_FAILURE, null, USERNAME,
                "BadCredentialsException");
    }

    /**
     * A blank name is recorded as no name.
     */
    @Test
    void publishAuthenticationSuccess_whenNameIsBlank_recordsNoUsername() {
        publisher.publishAuthenticationSuccess(UsernamePasswordAuthenticationToken.unauthenticated(" ", SECRET));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.LOGIN_SUCCESS, null, null, null);
    }

    /**
     * An OAuth2 client authentication is not a login.
     */
    @Test
    void publishAuthenticationFailure_whenClientAuthentication_recordsNothing() {
        publisher.publishAuthenticationFailure(new BadCredentialsException("x"),
                new OAuth2ClientAuthenticationToken("client", ClientAuthenticationMethod.CLIENT_SECRET_BASIC, SECRET,
                        null));

        verifyNoInteractions(recordSecurityEventUseCase);
    }

    /**
     * A bearer token of the API is not a login.
     */
    @Test
    void publishAuthenticationSuccess_whenBearerToken_recordsNothing() {
        publisher.publishAuthenticationSuccess(new BearerTokenAuthenticationToken("token"));

        verifyNoInteractions(recordSecurityEventUseCase);
    }
}
