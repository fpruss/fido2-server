package org.pruss.fido2server.service;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.AllArgsConstructor;
import org.pruss.fido2server.data.ApplicationUser;
import org.pruss.fido2server.data.Authenticator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.yubico.webauthn.data.PublicKeyCredential.parseAssertionResponseJson;
import static com.yubico.webauthn.data.UserVerificationRequirement.REQUIRED;
import static java.util.Objects.requireNonNull;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class RegistrationService {

    private final RelyingParty relyingParty;

    public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(UserIdentity userIdentity) {
        AuthenticatorSelectionCriteria authenticatorSelectionCriteria = AuthenticatorSelectionCriteria.builder()
                .userVerification(REQUIRED)
                .build();
        StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(authenticatorSelectionCriteria)
                .build();
        return relyingParty.startRegistration(registrationOptions);
    }

    public Authenticator finishRelyingPartyRegistration(ApplicationUser user, HttpSession session, String credential, String tokenName) throws IOException, RegistrationFailedException, NullPointerException {
        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc = PublicKeyCredential.parseRegistrationResponseJson(credential);
        FinishRegistrationOptions options = getFinishRegistrationOptions(user, session, pkc);
        RegistrationResult result = relyingParty.finishRegistration(options);
        return new Authenticator(result, pkc.getResponse(), user, tokenName);
    }

    public AssertionResult buildAssertionResult(String credential, String username, HttpSession session) throws AssertionFailedException, IOException {
        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc = parseAssertionResponseJson(credential);
        AssertionRequest request = (AssertionRequest) session.getAttribute(username);
        return relyingParty.finishAssertion(FinishAssertionOptions.builder()
                .request(request)
                .response(pkc)
                .build());
    }

    public AssertionRequest buildAssertionRequest(String username) {
        return relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(username)
                .userVerification(REQUIRED)
                .build());
    }

    private PublicKeyCredentialCreationOptions getRequestOptions(ApplicationUser user, HttpSession session) {
        return (PublicKeyCredentialCreationOptions) session.getAttribute(user.getUsername());
    }

    private FinishRegistrationOptions getFinishRegistrationOptions(ApplicationUser user, HttpSession session, PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc) {
        PublicKeyCredentialCreationOptions requestOptions = requireNonNull(getRequestOptions(user, session));
        return FinishRegistrationOptions.builder()
                .request(requestOptions)
                .response(pkc)
                .build();
    }
}
