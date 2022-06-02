package org.pruss.fido2server.data;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.HexFormat;
import java.util.Optional;

import static com.google.common.collect.Iterables.getOnlyElement;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@DataJpaTest
public class AuthenticatorRepositoryTest {

    @Mock
    private RegistrationResult result;
    @Mock
    private AuthenticatorAttestationResponse response;
    @Mock
    private ApplicationUser user;
    @Mock
    private AttestationObject attestationObject;
    @Mock
    private AttestedCredentialData attestedCredentialData;
    @Mock
    private AuthenticatorData authenticatorData;
    @Mock
    private PublicKeyCredentialDescriptor publicKeyCredentialDescriptor;

    @Autowired
    private AuthenticatorRepository repository;
    private ByteArray byteArray;

    @BeforeEach
    public void setUp() {
        byteArray = new ByteArray(HexFormat.of().parseHex("e04fd020ea3a6910a2d808002b30309d"));
        Optional<AttestedCredentialData> optionalOfAttestedCredentialData = Optional.of(attestedCredentialData);
        when(response.getAttestation()).thenReturn(attestationObject);
        when(attestationObject.getAuthenticatorData()).thenReturn(authenticatorData);
        when(authenticatorData.getAttestedCredentialData()).thenReturn(optionalOfAttestedCredentialData);
        when(result.getKeyId()).thenReturn(publicKeyCredentialDescriptor);
        when(publicKeyCredentialDescriptor.getId()).thenReturn(byteArray);
        when(result.getPublicKeyCose()).thenReturn(byteArray);
        when(attestedCredentialData.getAaguid()).thenReturn(byteArray);
        when(result.getSignatureCount()).thenReturn(1L);
    }
//TODO fix test, write new tests
//    @Test
//    public void test_save_and_find_by_id() {
//        Authenticator authenticator = new Authenticator(result, response, user, "testuser");
//        repository.save(authenticator);
//        Authenticator retrievedAuthenticator = getOnlyElement(repository.findAll());
//        assertThat(authenticator).isEqualTo(retrievedAuthenticator);
//    }

//    @Test
//    public void test_that_one_user_can_have_multiple_authenticators() {
//        Authenticator authenticator = new Authenticator(result, response, user, "testuser");
//        Authenticator authenticator2 = new Authenticator(result, response, user, "testuser");
//    }
}
