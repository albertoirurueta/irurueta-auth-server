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

package com.irurueta.authserver.authorization.api.web.totp;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceCookieWriter;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceFactor;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceFilter;
import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.application.mfa.FindTrustedDeviceUseCase;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

/**
 * Wires the TOTP second factor into the login/UI chain. The filters are built here and handed to the customizer,
 * never declared as beans: Spring Boot would register every {@code Filter} bean in the servlet container, outside
 * the security chain.
 */
@Configuration(proxyBeanMethods = false)
public class TotpConfiguration {

    /**
     * Installs the TOTP second factor in the login/UI chain.
     *
     * @param totpCodeVerifier           verifies a posted code with the use case of its kind.
     * @param createTrustedDeviceUseCase remembers a device.
     * @param findTrustedDeviceUseCase   finds a remembered device.
     * @param userResolver               resolves the identifier of the account of the signed-in user.
     * @param factorGrantor              adds the factor authority to an authentication.
     * @param cookieWriter               writes the cookie of a remembered device.
     * @param pendingRecoveryCodes       keeps the recovery codes of an enrolment until they are shown.
     * @return the customizer.
     */
    @Bean
    @Order(1)
    public LoginChainCustomizer totpChainCustomizer(final TotpCodeVerifier totpCodeVerifier,
            final CreateTrustedDeviceUseCase createTrustedDeviceUseCase,
            final FindTrustedDeviceUseCase findTrustedDeviceUseCase, final SecondFactorUserResolver userResolver,
            final FactorGrantor factorGrantor, final TrustedDeviceCookieWriter cookieWriter,
            final PendingRecoveryCodes pendingRecoveryCodes) {
        final var provider = new TotpAuthenticationProvider(totpCodeVerifier, userResolver, factorGrantor);
        final var totpFilter = new TotpAuthenticationFilter(new ProviderManager(provider),
                createTrustedDeviceUseCase, userResolver, cookieWriter, pendingRecoveryCodes);
        final var trustedDeviceFilter = new TrustedDeviceFilter(findTrustedDeviceUseCase, factorGrantor,
                new HttpSessionSecurityContextRepository(),
                new SavedRequestAwareAuthenticationSuccessHandler(), TrustedDeviceFactor.AUTHORITY);
        return new TotpChainCustomizer(trustedDeviceFilter, totpFilter);
    }
}
