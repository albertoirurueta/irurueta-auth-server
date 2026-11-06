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

package com.irurueta.authserver.authorization.api.web.consent;

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.stereotype.Component;

/**
 * Points the authorization endpoint at the custom consent page instead of the framework's generated one.
 */
@Component
@Order(20)
public class ConsentProtocolCustomizer implements ProtocolChainCustomizer {

    @Override
    public void customize(final OAuth2AuthorizationServerConfigurer server) {
        server.authorizationEndpoint(endpoint -> endpoint.consentPage(ConsentController.CONSENT_PATH));
    }
}
