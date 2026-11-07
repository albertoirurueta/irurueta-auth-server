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

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.DevSmsInboxPageApi;
import com.irurueta.authserver.authorization.domain.sms.SmsInbox;
import com.irurueta.authserver.authorization.domain.sms.SmsInboxEntry;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;

/**
 * Development only ({@code dev} profile): renders the SMS messages the logging sender recorded instead of sending
 * them, so a developer or an end-to-end test can read the code of a sign-in or of a phone enrolment. The page is as
 * the contract {@code apis/auth-server/web-pages/auth-server-pages-v1.yaml} describes it through the generated
 * {@link DevSmsInboxPageApi}. The inbox exists only while the logging sender is in use, so it is looked up
 * lazily: with a real gateway configured the page is empty. It is a documented exception to the rule that
 * {@code src/main} holds no demo-only code (the end-to-end tests run the packaged jar, so it cannot live in
 * {@code src/test}); it is inert in every other profile because the controller is not even created.
 */
@Controller
@Profile("dev")
@RequiredArgsConstructor
public class DevSmsInboxController implements DevSmsInboxPageApi {

    /** Path of the page, taken from the contract. */
    public static final String DEV_SMS_INBOX_PATH = PATH_DEV_SMS_INBOX_PAGE;

    /** Name of the template of the page. */
    static final String VIEW_NAME = "dev-sms-inbox";

    /** Name of the model attribute that holds the recorded messages. */
    static final String MESSAGES_ATTRIBUTE = "messages";

    /** The inbox of the logging sender; absent when a real gateway sends the messages. */
    private final ObjectProvider<SmsInbox> smsInbox;

    /** Renders the page. */
    private final PageRenderer pageRenderer;

    /**
     * Renders the recorded messages.
     *
     * @return the page, never cached because the messages carry codes.
     */
    @Override
    public ResponseEntity<String> devSmsInboxPage() {
        final var inbox = smsInbox.getIfAvailable();
        final var entries = inbox == null ? List.<SmsInboxEntry>of() : inbox.entries();
        final var page = pageRenderer.render(VIEW_NAME, Map.of(MESSAGES_ATTRIBUTE, entries));
        return ResponseEntity.status(page.getStatusCode())
                .headers(page.getHeaders())
                .cacheControl(CacheControl.noStore())
                .body(page.getBody());
    }
}
