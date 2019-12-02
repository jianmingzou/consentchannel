package com.example.consentchannel.model;

import java.util.UUID;
import lombok.Builder;
import lombok.ToString;

@Builder
@ToString
public class ConsentInitiationRequest {

        public String accessTokenScope;
        public String requestScope;
        public String intentId;
        public String redirectUri;
        @Builder.Default
        public String correlationId = UUID.randomUUID().toString();
        @Builder.Default
        public String state = UUID.randomUUID().toString();
        @Builder.Default
        public String nonce = UUID.randomUUID().toString();
//        @Builder.Default
        public String responseType;
}
