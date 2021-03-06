package com.example.consentchannel.configuration;


import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

@Configuration
@ConfigurationProperties("com.example.consentchannel")
@Data
public class CredentialContext {

  private String internalClientId;

  private String internalClientSecret;

  private String oauthUri;

  private String consentMgtUri;

}
