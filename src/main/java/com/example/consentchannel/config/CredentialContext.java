package com.example.consentchannel.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Data
@Configuration
@Component
@ConfigurationProperties(prefix = "com.sample.consentchannel")
public class CredentialContext {

  private String internalClientId;
  private String internalClientSecret;
  private String oauth;
//  private String internalSystemAccessToken;

}
