package com.example.consentchannel.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RequestJwtClaimsWrapper {

    @JsonProperty("claims")
    private RequestJwtClaims requestJwtClaims;

}