package org.pruss.fido2server.service;

import com.yubico.webauthn.*;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.exception.AssertionFailedException;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpSession;
import java.io.IOException;

import static com.yubico.webauthn.data.PublicKeyCredential.parseAssertionResponseJson;

@Service
@AllArgsConstructor(onConstructor = @__(@Autowired))
public class RelyingPartyService {

    private final RelyingParty relyingParty;

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
                .build());
    }

}
