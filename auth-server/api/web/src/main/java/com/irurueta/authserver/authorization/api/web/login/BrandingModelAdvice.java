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
package com.irurueta.authserver.authorization.api.web.login;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

/**
 * Adds the {@link BrandingProperties} to the model of every server-rendered page as {@code branding}.
 */
@ControllerAdvice
@RequiredArgsConstructor
public class BrandingModelAdvice {

    /** Provider of the configured branding; absent in web slices that do not enable the properties. */
    private final ObjectProvider<BrandingProperties> branding;

    /**
     * Exposes the branding to the templates.
     *
     * @return the configured branding, or the defaults when the properties are not enabled.
     */
    @ModelAttribute("branding")
    public BrandingProperties branding() {
        return branding.getIfAvailable(() -> new BrandingProperties(null, null, null));
    }
}
