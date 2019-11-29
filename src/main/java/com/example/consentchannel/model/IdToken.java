package com.example.consentchannel.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class IdToken {

    @JsonProperty("openbanking_intent_id")
    private OpenBankingIntentId openBankingIntentId;

//    @SerializedName("acr")
//    private AuthenticationContextClassReference authenticationContextClassReference;



}
