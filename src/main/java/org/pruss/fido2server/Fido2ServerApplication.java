package org.pruss.fido2server;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.pruss.fido2server.config.WebAuthProperties;
import org.pruss.fido2server.data.RegistrationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan
public class Fido2ServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(Fido2ServerApplication.class, args);
    }

    @Bean
    @Autowired
    public RelyingParty relyingParty(RegistrationService registrationRepository, WebAuthProperties properties) {
        RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
                .id(properties.getHostName())
                .name(properties.getDisplay())
                .build();

        return RelyingParty.builder()
                .identity(rpIdentity)
                .credentialRepository(registrationRepository)
                .origins(properties.getOrigin())
                .build();
    }

}
