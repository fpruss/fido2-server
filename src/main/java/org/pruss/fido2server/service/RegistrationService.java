package org.pruss.fido2server.service;

import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.ApplicationUser;
import org.pruss.fido2server.data.Authenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Objects;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class RegistrationService {

    private final RelyingParty relyingParty;

    public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(UserIdentity userIdentity) {
        StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                .user(userIdentity)
                .build();
        return relyingParty.startRegistration(registrationOptions);
    }

    public Authenticator finishRelyingPartyRegistration(ApplicationUser user, HttpSession session, String credential, String credentialName) throws IOException, RegistrationFailedException, NullPointerException {
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential.parseRegistrationResponseJson(credential);
        FinishRegistrationOptions options = getFinishRegistrationOptions(user, session, pkc);
        RegistrationResult result = relyingParty.finishRegistration(options);
        return new Authenticator(result, pkc.getResponse(), user, credentialName);
    }

    private PublicKeyCredentialCreationOptions getRequestOptions(ApplicationUser user, HttpSession session) {
        return (PublicKeyCredentialCreationOptions) session.getAttribute(user.getUsername());
    }

    private FinishRegistrationOptions getFinishRegistrationOptions(ApplicationUser user, HttpSession session, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc) {
        PublicKeyCredentialCreationOptions requestOptions = Objects.requireNonNull(getRequestOptions(user, session));
        return FinishRegistrationOptions.builder()
                .request(requestOptions)
                .response(pkc)
                .build();
    }
}
