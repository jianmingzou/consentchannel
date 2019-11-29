package com.example.consentchannel.service;

import com.example.consentchannel.config.CredentialContext;
import com.fasterxml.jackson.databind.JsonNode;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestTemplate;

@Service
public class AccessService {

    private final static Logger LOGGER = LoggerFactory.getLogger(AccessService.class);
    private final RestTemplate restTemplate;
    private final CredentialContext credentialContext;

    @Autowired
    public AccessService(final RestTemplate restTemplate, CredentialContext credentialContext){

        this.restTemplate = restTemplate;
        this.credentialContext = credentialContext;
    }

    public String generateAccessTokenForAccountRequest() throws Exception {

        HttpHeaders headers =
                buildHeaders(credentialContext.getInternalClientId(), credentialContext.getInternalClientSecret());

        return generateAccessToken(headers, "accounts");
    }

    protected HttpHeaders buildHeaders(String apiKey, String apiSecret) {

        HttpHeaders headers = buildHeaders(false);

        String plainCredentials = new StringBuilder(apiKey).append(":").append(apiSecret).toString();
        byte[] plainCredsBytes = plainCredentials.getBytes();
        String base64Credentials = Base64.getEncoder().encodeToString(plainCredsBytes);
        LOGGER.info("authorization: {}" , base64Credentials);
        headers.add("Authorization", "Basic " + base64Credentials);

        return headers;
    }

    public String generateAccessToken(HttpHeaders headers, String scope) {

        ResponseEntity<JsonNode> response = generateAccessTokenResponse(headers, scope, HttpMethod.POST);

        JsonNode responseBody = response.getBody();
        System.out.println("responseBody: " + responseBody);
        return responseBody.get("access_token").asText();
    }

    public ResponseEntity<JsonNode> generateAccessTokenResponse(HttpHeaders headers, String scope,
            HttpMethod httpMethod) {

        URI oauthTokenUri = null;

        MultiValueMap<String, String> postParamsMap = new LinkedMultiValueMap<String, String>();

//        String tokenUrl = apigeeConfig.getApigeeTokenUrl();
        String tokenUrl = "http://xxx/oauth/";



        if (httpMethod.equals(HttpMethod.GET)) {

//            oauthTokenUri = buildClientCredentialsGrantTypeRequest(tokenUrl, scope);

        } else {

            //            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            try {

                oauthTokenUri = new URI(tokenUrl);

            } catch (URISyntaxException e) {
                LOGGER.error("Unable to build uri", e);
            }
            postParamsMap.add("grant_type", "client_credentials");

            if (!StringUtils.isEmpty(scope)) {
                postParamsMap.add("scope", scope);
            }

        }

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(postParamsMap, headers);

//        RestTemplate restTemplate = useExternalRestTemplate ? externalRestTemplate : internalRestTemplate;

        return restTemplate.exchange(oauthTokenUri, httpMethod, request, JsonNode.class);
    }


    protected HttpHeaders buildHeaders(boolean isFormUrlEncoded) {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(
                isFormUrlEncoded ? MediaType.APPLICATION_FORM_URLENCODED : MediaType.APPLICATION_JSON);

        if (!isFormUrlEncoded) {
            headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
        }

        return headers;
    }
}
