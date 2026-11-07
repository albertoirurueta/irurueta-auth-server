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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsInbox;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;

/** Unit tests of {@link DevSmsInboxController}. */
@ExtendWith(MockitoExtension.class)
class DevSmsInboxControllerTest {

    /** The inbox of the logging sender, when there is one. */
    @Mock
    private ObjectProvider<SmsInbox> smsInbox;

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Controller under test. */
    @InjectMocks
    private DevSmsInboxController controller;

    /** The recorded messages are rendered and the page is never cached. */
    @Test
    void devSmsInboxPage_whenTheLoggingSenderIsInUse_rendersItsMessages() {
        final var entry = new SmsInboxEntry(new PhoneNumber("+34600111222"), "Your code is 123456", Instant.EPOCH);
        final var inbox = mock(SmsInbox.class);
        when(inbox.entries()).thenReturn(List.of(entry));
        when(smsInbox.getIfAvailable()).thenReturn(inbox);
        when(pageRenderer.render(eq("dev-sms-inbox"), anyMap())).thenReturn(ResponseEntity.ok("<html></html>"));

        final var response = controller.devSmsInboxPage();

        assertEquals("<html></html>", response.getBody());
        assertEquals("no-store", response.getHeaders().getCacheControl());
        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("dev-sms-inbox"), model.capture());
        assertEquals(Map.of("messages", List.of(entry)), model.getValue());
    }

    /** With a real gateway there is no inbox: the page is empty. */
    @Test
    void devSmsInboxPage_whenARealGatewayIsConfigured_rendersNoMessages() {
        when(smsInbox.getIfAvailable()).thenReturn(null);
        when(pageRenderer.render(eq("dev-sms-inbox"), anyMap())).thenReturn(ResponseEntity.ok("<html></html>"));

        controller.devSmsInboxPage();

        final var model = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq("dev-sms-inbox"), model.capture());
        assertEquals(Map.of("messages", List.of()), model.getValue());
    }

    /** The controller only exists in the dev profile. */
    @Test
    void controller_whenInspected_isDevProfileOnly() {
        assertEquals("dev", DevSmsInboxController.class.getAnnotation(Profile.class).value()[0]);
        assertEquals("/dev/sms-inbox", DevSmsInboxController.DEV_SMS_INBOX_PATH);
    }
}
