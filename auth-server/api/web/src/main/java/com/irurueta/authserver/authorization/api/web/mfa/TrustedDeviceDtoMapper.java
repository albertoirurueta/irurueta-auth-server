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

import com.irurueta.authserver.authorization.api.web.v1.generated.model.TrustedDeviceResponse;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the trusted devices of the domain onto the DTO generated from the contract, so a domain model is never
 * returned from {@link TrustedDeviceController}. The hash of the device token never leaves the server.
 */
@Component
public class TrustedDeviceDtoMapper {

    /**
     * Maps a device to its public view.
     *
     * @param device the device.
     * @return its public view.
     */
    public TrustedDeviceResponse toResponse(final TrustedDevice device) {
        return new TrustedDeviceResponse(
                device.id(), device.userAgentSummary(), device.createdAt(), device.expiresAt());
    }

    /**
     * Maps several devices, keeping their order.
     *
     * @param devices the devices.
     * @return their public views.
     */
    public List<TrustedDeviceResponse> toResponses(final List<TrustedDevice> devices) {
        return devices.stream().map(this::toResponse).toList();
    }
}
