package org.pruss.fido2server.service;

import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.Authenticator;
import org.pruss.fido2server.data.CredentialRepositoryImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class AuthenticatorService {

    private final CredentialRepositoryImpl credentialRepositoryImpl;

    public void save(Authenticator authenticator) {
        credentialRepositoryImpl.getAuthenticatorRepository().save(authenticator);
    }
}
