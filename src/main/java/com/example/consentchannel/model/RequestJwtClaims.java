package com.example.consentchannel.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RequestJwtClaims {

    @JsonProperty("userinfo")
    private UserInfo userInfo;

    @JsonProperty("id_token")
    private IdToken idToken;

}