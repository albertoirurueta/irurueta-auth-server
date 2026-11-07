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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttKind;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/** Unit tests of {@link OttAuthenticationSuccessHandler}. */
@ExtendWith(MockitoExtension.class)
class OttAuthenticationSuccessHandlerTest {

    /** Resumes the interrupted request. */
    @Mock
    private AuthenticationSuccessHandler delegate;

    /** Handler under test. */
    @InjectMocks
    private OttAuthenticationSuccessHandler handler;

    /** The pending token is forgotten and the delegate resumes the request. */
    @Test
    void onAuthenticationSuccess_whenSignedIn_clearsThePendingTokenAndDelegates() throws Exception {
        final var request = new MockHttpServletRequest();
        new PendingOtt("alice", "binding", OttKind.CODE, OttPurpose.LOGIN, OttChannel.EMAIL)
                .saveTo(request.getSession());
        final var response = new MockHttpServletResponse();
        final var authentication = UsernamePasswordAuthenticationToken.authenticated("alice", "x",
                AuthorityUtils.NO_AUTHORITIES);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertTrue(PendingOtt.of(request).isEmpty());
        verify(delegate).onAuthenticationSuccess(request, response, authentication);
    }
}
