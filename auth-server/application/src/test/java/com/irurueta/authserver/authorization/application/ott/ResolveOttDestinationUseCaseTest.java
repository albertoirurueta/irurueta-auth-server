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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ResolveOttDestinationUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ResolveOttDestinationUseCaseTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** E-mail used by the tests. */
    private static final String EMAIL = "alice@example.test";

    /** Phone used by the tests. */
    private static final String PHONE = "+34600000000";

    /** Identifier of the account. */
    private static final UUID ID = UUID.randomUUID();

    /** Use case that finds an account. */
    @Mock
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Port that reads the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Use case under test. */
    @InjectMocks
    private ResolveOttDestinationUseCase useCase;

    /**
     * Verifies that the verified e-mail of an enabled account is the destination.
     */
    @Test
    void execute_whenEmailIsVerified_returnsEmailDestination() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(true, EMAIL, true)));

        final var destination = useCase.execute(USERNAME, OttChannel.EMAIL);

        assertEquals(new OttDestination(ID, OttChannel.EMAIL, EMAIL), destination.orElseThrow());
    }

    /**
     * Verifies that an unverified e-mail is not a destination.
     */
    @Test
    void execute_whenEmailIsNotVerified_returnsEmpty() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(true, EMAIL, false)));

        assertTrue(useCase.execute(USERNAME, OttChannel.EMAIL).isEmpty());
    }

    /**
     * Verifies that an account without e-mail has no e-mail destination.
     */
    @Test
    void execute_whenAccountHasNoEmail_returnsEmpty() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(true, null, true)));

        assertTrue(useCase.execute(USERNAME, OttChannel.EMAIL).isEmpty());
    }

    /**
     * Verifies that a disabled account has no destination in either channel, without reading its phone.
     */
    @Test
    void execute_whenAccountIsDisabled_returnsEmpty() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(false, EMAIL, true)));

        assertTrue(useCase.execute(USERNAME, OttChannel.EMAIL).isEmpty());
        assertTrue(useCase.execute(USERNAME, OttChannel.SMS).isEmpty());
        verifyNoInteractions(userPhoneRepository);
    }

    /**
     * Verifies that an unknown user has no destination.
     */
    @Test
    void execute_whenAccountIsUnknown_returnsEmpty() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USERNAME, OttChannel.SMS).isEmpty());
    }

    /**
     * Verifies that a blank username is not even looked up.
     */
    @Test
    void execute_whenUsernameIsBlank_returnsEmptyWithoutLookup() {
        assertTrue(useCase.execute(" ", OttChannel.EMAIL).isEmpty());
        assertTrue(useCase.execute(null, OttChannel.EMAIL).isEmpty());

        verifyNoInteractions(findUserAccountUseCase);
    }

    /**
     * Verifies that the verified phone of an enabled account is the SMS destination.
     */
    @Test
    void execute_whenPhoneIsVerified_returnsSmsDestination() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(true, EMAIL, false)));
        when(userPhoneRepository.findByUserId(ID))
                .thenReturn(Optional.of(new UserPhone(ID, new PhoneNumber(PHONE), Instant.EPOCH)));

        final var destination = useCase.execute(USERNAME, OttChannel.SMS);

        assertEquals(new OttDestination(ID, OttChannel.SMS, PHONE), destination.orElseThrow());
    }

    /**
     * Verifies that an account without a verified phone has no SMS destination.
     */
    @Test
    void execute_whenPhoneIsMissing_returnsEmpty() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account(true, EMAIL, true)));
        when(userPhoneRepository.findByUserId(ID)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USERNAME, OttChannel.SMS).isEmpty());
    }

    /**
     * Builds an account.
     *
     * @param enabled       whether the account is enabled.
     * @param email         the e-mail, or {@code null}.
     * @param emailVerified whether the e-mail is verified.
     * @return the account.
     */
    private static UserAccount account(final boolean enabled, final String email, final boolean emailVerified) {
        return new UserAccount(ID, USERNAME, "encoded", enabled, List.of(), email, emailVerified,
                UserAccount.DEFAULT_TENANT);
    }
}
