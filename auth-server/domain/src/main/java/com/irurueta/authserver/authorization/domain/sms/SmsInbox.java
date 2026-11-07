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
package com.irurueta.authserver.authorization.domain.sms;

import java.util.List;

/**
 * Port that lists the messages a development sender recorded instead of sending them. Only the logging sender has
 * one, so it is absent whenever a real gateway is configured. An implementation never returns {@code null}.
 */
public interface SmsInbox {

    /**
     * Lists the recorded messages.
     *
     * @return a snapshot of the messages, oldest first; never modifiable by the caller.
     */
    List<SmsInboxEntry> entries();
}
