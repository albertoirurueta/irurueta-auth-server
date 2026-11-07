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
package com.irurueta.authserver.authorization.api.web.x509;

import com.irurueta.authserver.authorization.api.web.v1.generated.model.Certificate;
import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Maps the certificate bindings of the domain onto the DTO generated from the contract. The account a binding belongs
 * to is not part of the contract.
 */
@Component
public class CertificateDtoMapper {

    /**
     * Maps a binding to its public view.
     *
     * @param binding the binding.
     * @return its public view.
     */
    public Certificate toResponse(final CertificateBinding binding) {
        return new Certificate(binding.id(), binding.fingerprintSha256(), binding.subjectDn(), binding.createdAt());
    }

    /**
     * Maps several bindings, keeping their order.
     *
     * @param bindings the bindings.
     * @return their public views.
     */
    public List<Certificate> toResponses(final List<CertificateBinding> bindings) {
        return bindings.stream().map(this::toResponse).toList();
    }
}
