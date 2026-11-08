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
package com.irurueta.authserver.authorization.application.x509;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
import com.irurueta.authserver.authorization.domain.x509.CertificateBindingRepository;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that lists the client certificates bound to an account.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ListCertificatesUseCase {

    /** Port that stores the bindings. */
    private final CertificateBindingRepository certificateBindingRepository;

    /**
     * Lists the certificates of an account, oldest first.
     *
     * @param userId identifier of the account.
     * @return the bindings, possibly empty.
     */
    public List<CertificateBinding> execute(final UUID userId) {
        return certificateBindingRepository.findByUser(userId);
    }
}
