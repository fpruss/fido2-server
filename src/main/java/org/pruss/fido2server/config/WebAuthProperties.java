package org.pruss.fido2server.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Set;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "authn")
public class WebAuthProperties {
    private String hostName;
    private String display;
    private Set<String> origin;
}
