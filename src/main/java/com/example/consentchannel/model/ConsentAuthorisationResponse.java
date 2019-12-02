package com.example.consentchannel.model;


import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class ConsentAuthorisationResponse {

    @JsonProperty("redirect_uri")
    String redirectUri;
}
