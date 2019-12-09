package com.example.consentchannel.controller;

import com.example.consentchannel.configuration.CredentialContext;
import com.example.consentchannel.model.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import javax.websocket.server.PathParam;

import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
public class ConsentChannelController {


    private final String ID_TOKEN = "eyJ0eXAiOiJKV1QiLCJraWQiOiJhaWItc2lnbmVyLXNhbXBsZS12MS1ST0kiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1zaXQtaW50ZXJuYWwuYWlidGVzdC5pZSIsImF1ZCI6IlZVRGtWUHNKeVlDWHZxWnRzTENFS3pkNlpVYVVyU2xmIiwic3ViIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6NWM2YTI2YjctMmQyMi00Zjc5LWFmY2ItM2NiZDdiYjFjYTdhIiwib3BlbmJhbmtpbmdfaW50ZW50X2lkIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6NWM2YTI2YjctMmQyMi00Zjc5LWFmY2ItM2NiZDdiYjFjYTdhIiwiYWNyIjoidXJuOm9wZW5iYW5raW5nOnBzZDI6c2NhIiwiZXhwIjoxNTc1MDIxNjMwLCJpYXQiOjE1NzUwMjEzMzAsIm5vbmNlIjoiN2FmN2NiYWItMzc3NS00NTUxLTg2MDQtNjU5ZmIyYjFmNjM1Iiwic19oYXNoIjoibFZESjRocGlVVFVhakN5WDlyVkZmQSIsImNfaGFzaCI6IkRQM2tZOXhJWjJOREZ1UVZrb0JNRWcifQ.oVTePpMBkmvxQxAByHsxqx13MkHJWPMBZdMkJgnwuCZSgIbOfKRKv5HHTqpusYap-dsCyfJIXBKZ5AXMNAtWnwpFT_AeIW3POetvukt05FWS_Sd6m-kUMiiGvZwZD2RfzYHgcuYCoYfxt4Ntd-eU8W_sz1YwwDtPBWUEBfHp8bOnzAKPI2gBWr1AMEL-miMv1d21lEWBPNVaKxuTY4Sw_wKf2rfvvM9BXszDTiKef-nuqLHxdDOCmfOrc3luSzNaWIj7rHtalJnyqPzic2oes6zK1pWsJB9q1VaDCQMbv7a9ExhgHcyxHXcWKwkA18dUUiZ8cPpsR6i1M-8hzh0jZw";
    private final ObjectMapper objectMapper;

    private final RestTemplate restTemplate;
    private final CredentialContext credentialContext;

    @Autowired
    public ConsentChannelController(
            RestTemplate restTemplate,
            CredentialContext credentialContext,
            ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.credentialContext = credentialContext;
        LOGGER.info("credentialContext [{}]", credentialContext);
        this.objectMapper = objectMapper;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentChannelController.class);


    @GetMapping("/consent/ping")
    @ResponseBody
    public ResponseEntity<?> pingConsent(@RequestParam("echo") String echo) {

        LOGGER.info("pingConsent [{}]", echo);
        return ResponseEntity.ok(echo);
    }


    @PostMapping("/consent/redirect")
    @ResponseBody
    public ResponseEntity<?> redirect(@RequestParam("code") String code) {
//        code=WrRTWUS1eVU9yYNY6LfGoKHc6pvx8wIAIPVhaXzO
        LOGGER.info("redirect received [{}]", code);
        return ResponseEntity.ok("received");
    }
    /**
     * Init consent
     * ?correlation_id=5223927d-6cfe-4ecd-b73b-d8b0f0c54764 &query_string=client_id%253DSwCIxkpf8em1ZbS5CM7MRSh9PnheUNNd%2526scope%253Dopenid+accounts%2526redirect_uri%253Dhttp%253A%252F%252Flocalhost%253A8585%252FredirectMe%2526response_type%253Dcode+id_token%2526someOtherParam%253Dblahblah%2526request%253DeyJraWQiOiJzYW1wbGVUcHBLaWQiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6IlN3Q0l4a3BmOGVtMVpiUzVDTTdNUlNoOVBuaGVVTk5kIiwiYXVkIjoiaHR0cHM6Ly9haWItcHJvZC1wcm9kLmFwaWdlZS5uZXQiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyIsInN0YXRlIjoiOWU3MjY3NDgtYzExOS00NmRkLTg0ZGMtMjQxY2MzOWQ2ZDdjIiwibm9uY2UiOiJmNWNjYWQ1Zi0yMzdkLTQzNTYtYmNiNi0yM2M2YmZmMTBhNDUiLCJtYXhfYWdlIjoiODY0MDAwMCIsImlhdCI6MTU3NDk0MzcxNCwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4NTg1L3JlZGlyZWN0TWUiLCJjbGFpbXMiOnsidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6MTE3ZDU0NDMtNGVkNS00Njg5LWE5MjMtNjAxMDk4ZmYyNzQ0IiwiZXNzZW50aWFsIjp0cnVlfX0sImlkX3Rva2VuIjp7Im9wZW5iYW5raW5nX2ludGVudF9pZCI6eyJ2YWx1ZSI6InVybjphaWI6YXBpZ2F0ZXdheTpvcGVuLWJhbmtpbmc6YWlzcDphY2NvdW50LWFjY2Vzcy1jb25zZW50czp2My4xOjExN2Q1NDQzLTRlZDUtNDY4OS1hOTIzLTYwMTA5OGZmMjc0NCIsImVzc2VudGlhbCI6dHJ1ZX0sImFjciI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJ1cm46YWliOmFwaWdhdGV3YXk6b3Blbi1iYW5raW5nOmFpc3A6YWNjb3VudC1hY2Nlc3MtY29uc2VudHM6djMuMToxMTdkNTQ0My00ZWQ1LTQ2ODktYTkyMy02MDEwOThmZjI3NDQiXX19fSwiZXhwIjoxNTc0OTQ3MzE0fQ.FsCGyN3O5GQ2DtjIHDQgNrqi2av3rzu2LJsWj5ZhYE5bDvGvyacn89kIeCZToDXQKGX_4LvTRWcto4jXISI8voyyBL9Prb4TDynlgXpOJ1PIV5Xs9NbkWNnJRuLWgShzw_OlNruZlD3AR61KbN9SvxLTin3ds_0DVwZX1FS0PgBz33LqWffhhKal0V4FUTqD1FUKMP6Q-8WqeyHOhCMqUqVM3S32tfin7RMODzZeS75_FZxgr199i8BVllgGBMx4nnvVwEL1P3SAa49H5OF4cvbsGvoj5TUXua31c4z1ximxCkhwx2-JBoQHtQ91fGm3hknDFxfg8mNEBJ6cRVZhWQ%2526state%253D9e726748-c119-46dd-84dc-241cc39d6d7c%2526nonce%253Df5ccad5f-237d-4356-bcb6-23c6bff10a45
     */
    @PostMapping("/consent/init")
    @ResponseBody
    public ResponseEntity<?> initConsent(
            @RequestParam("correlation_id") String correlationId,
            @RequestParam("query_string") String queryString) {

        LOGGER.info("correlation_id [{}] and query_string [{}], intent id [{}]", correlationId, queryString);

        try {
            // found the consent and set status
            String consentId = extractConsentId(extractQueryString(queryString, "request"));
            try {
                ObjectNode objectNode = getConsent(consentId);
                setConsentStatus(ConsentStatus.AUTHORISED, objectNode);
            }catch (Exception e) {
                LOGGER.info("could not found consent by [{}]", consentId);
            }
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(extractQueryString(queryString, "redirect_uri")).append("?scope=accounts");
            String accessToken = getAccessToken();
//            String authCode = authorizationCode(accessToken);
            String authCode = exchangeAccessToken();
            stringBuilder.append("&code=").append(authCode);
            stringBuilder.append("&state=").append(UUID.randomUUID().toString());
            stringBuilder.append("&id_token=").append(ID_TOKEN);
            ConsentAuthorisationResponse consentAuthorisationResponse = new ConsentAuthorisationResponse();
            consentAuthorisationResponse.setRedirectUri(stringBuilder.toString());

            return ResponseEntity.ok(consentAuthorisationResponse);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ExceptionUtils.getStackTrace(e));
        }
    }

    protected String extractQueryString(String queryString, String extractKey)
            throws MalformedURLException, UnsupportedEncodingException {

        String decodedRequest = URLDecoder.decode(queryString, StandardCharsets.UTF_8.name());
        LOGGER.info("decoded request: [{}]", decodedRequest);

        Map<String, String> queryPairs = new LinkedHashMap<>();

        String[] pairs = decodedRequest.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(
                    URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        LOGGER.info("Query parameters [{}]", queryPairs);

        return queryPairs.get(extractKey);
    }

    protected String extractConsentId(String jwt) throws Exception {
        if (StringUtils.isBlank(jwt)) {
            LOGGER.info("jwt received is blank");
            throw new Exception("JWT is blank");
        }

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setSkipSignatureVerification()
                .build();

        try {
            //  Validate the JWT and process it to the Claims
            JwtClaims jwtClaims = jwtConsumer.processToClaims(jwt);
            String rawJson = jwtClaims.getRawJson();
//                RequestJwtClaimsWrapper requestJwtClaimsWrapper = objectMapper.readValue(rawJson, RequestJwtClaimsWrapper.class);
            RequestJwtClaimsWrapper requestJwtClaimsWrapper = objectMapper
                    .readValue(rawJson, RequestJwtClaimsWrapper.class);
            LOGGER.info("requestJwtClaimsWrapper: [{}]", requestJwtClaimsWrapper);

            return requestJwtClaimsWrapper.getRequestJwtClaims().getIdToken().getOpenBankingIntentId().getValue();


        } catch (InvalidJwtException e) {
            LOGGER.error("Internal user JWT invalid! " + e);
            throw new Exception("Internal user JWT invalid");
        } catch (Exception e) {
            LOGGER.error("claim allowed_accounts is invalid " + e);
            throw e;
        }
    }


    private String extractIntentId(RequestJwtClaimsWrapper requestJwtClaimsWrapper) throws Exception {

        String userInfoOpenBankingIntentId = null;
        String idTokenOpenBankingIntentId = null;

        if (requestJwtClaimsWrapper != null) {

            RequestJwtClaims requestJwtClaims = requestJwtClaimsWrapper.getRequestJwtClaims();

            if (requestJwtClaims != null) {

                userInfoOpenBankingIntentId = extractOpenBankingIntentId(requestJwtClaims.getUserInfo());

            }
        }


        if (StringUtils.isEmpty(userInfoOpenBankingIntentId)) {
            throw new Exception("cannot extract intent id from jwt");
        }

        return userInfoOpenBankingIntentId;
    }

    private String extractOpenBankingIntentId(UserInfo openBankingIntent) {

        if (openBankingIntent != null) {

            OpenBankingIntentId openBankingIntentId = openBankingIntent.getOpenBankingIntentId();

            if (openBankingIntentId != null) {

                return openBankingIntentId.getValue();
            }
        }

        return null;
    }


    private ObjectNode getConsent(String consentId) throws Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getConsentMgtUri() + "/" + consentId);

        URI consentInitiationUri = uriComponentsBuilder.build().toUri();
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<ObjectNode> request = new HttpEntity<>(headers);

        try {

            ResponseEntity<ObjectNode> response =
                    restTemplate.exchange(consentInitiationUri, HttpMethod.GET, request, ObjectNode.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                LOGGER.info("found the consent in consent management");
                return response.getBody();
            }
            else {
                throw new Exception("Consent not found");
            }

        } catch (HttpStatusCodeException e) {
            LOGGER.error("Error:", e);
            throw new Exception("Consent not found");
        }
    }

    private void setConsentStatus(ConsentStatus consentStatus, ObjectNode objectNode) throws Exception {
        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getConsentMgtUri());

        URI consentUri = uriComponentsBuilder.build().toUri();
        HttpHeaders headers = new HttpHeaders();
        objectNode.put("status", consentStatus.name());
        HttpEntity<ObjectNode> request = new HttpEntity<>(objectNode, headers);

        try {

            ResponseEntity<ObjectNode> response =
                    restTemplate.exchange(consentUri, HttpMethod.PUT, request, ObjectNode.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                LOGGER.info("found the consent in consent management");
            }

        } catch (HttpStatusCodeException e) {
            LOGGER.error("Error:", e);
        }

    }
    private String authorizationCode(String accessToken) throws Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getOauthUri() + "/authorization.oauth2");

        URI authCodeURI = uriComponentsBuilder.build().toUri();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("client_id", "tpp1");
        parameters.add("client_secret", "2Federate");
        parameters.add("response_type", "code");
//        parameters.add("scope", "accounts");
//        parameters.add("state",  UUID.randomUUID().toString());
//        parameters.add("redirect_uri",  "https://google.com");
//        yzfuIiL7thF6-f3y4qgNZQacTqN8g9Wf-m6fsuNJ


        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
//        HttpEntity<JsonNode> request = new HttpEntity<>(headers);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(parameters, headers);

        try {
            LOGGER.info("uri [{}], request [{}]", authCodeURI, request);

            ResponseEntity<String> response =
                    restTemplate.exchange(authCodeURI, HttpMethod.POST, request, String.class);


            if (response.getStatusCode().is2xxSuccessful()) {
                LOGGER.info("get the auth code [{}]", response.getBody());
                //@TODO return auth code
//                return response.getBody().get("auth_code").asText();

            }

            return "ABCDEF";

        } catch (Exception e) {
//            LOGGER.error("Error:", e);
//            throw new Exception("error to retrieve auth code");
            LOGGER.error("cannot get a auth code", e);
            return "ABCDEF12345";
        }

    }


    private String getAccessToken() throws Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getOauthUri() + "/token.oauth2");

        URI authCodeURI = uriComponentsBuilder.build().toUri();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("scope", "accounts");
//        parameters.add("grant_type", "client_credentials");
        parameters.add("grant_type", "client_credentials");
//        parameters.add("response_type", "code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth("tpp1", "2Federate");
//        HttpEntity<JsonNode> request = new HttpEntity<>(headers);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(parameters, headers);

        try {

            LOGGER.info("uri [{}], request [{}]", authCodeURI, request);
            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(authCodeURI, HttpMethod.POST, request, JsonNode.class);


            if (response.getStatusCode().is2xxSuccessful()) {
                LOGGER.info("get the access toke [{}]", response.getBody());
                return response.getBody().get("access_token").asText();

            }

            return "ABCDEF";

        } catch (Exception e) {
//            LOGGER.error("Error:", e);
//            throw new Exception("error to retrieve auth code");
            LOGGER.error("cannot get access token", e);
            return "ABCDEF12345";
        }

    }

    private String exchangeAccessToken() throws Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getOauthUri() + "/authorization.oauth2");

        URI authCodeURI = uriComponentsBuilder.build().toUri();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add("scope", "accounts");
//        parameters.add("grant_type", "client_credentials");
        parameters.add("grant_type", "authorization_code");
        parameters.add("client_id", "tpp1");
        parameters.add("client_secret", "2Federate");
//        parameters.add("code", "yzfuIiL7thF6-f3y4qgNZQacTqN8g9Wf-m6fsuNJ");
        parameters.add("code", "i7pqEXYHrni2COCXbtjIz9yJ9m0Y7xyr8MAu5dgE");
        parameters.add("redirect_uri", "https://google.com");

        HttpHeaders headers = new HttpHeaders();

        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBasicAuth("joe", "2Federate");
//        HttpEntity<JsonNode> request = new HttpEntity<>(headers);
        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(parameters, headers);

        try {

            LOGGER.info("uri [{}], request [{}]", authCodeURI, request);
            ResponseEntity<String> response =
                    restTemplate.exchange(authCodeURI, HttpMethod.POST, request, String.class);


            if (response.getStatusCode().is2xxSuccessful()) {
                LOGGER.info("exchanged the access toke [{}]", response.getBody());
//                return response.getBody().get("access_token").asText();uri [https://ec2-34-246-195-42.eu-west-1.compute.amazonaws.com:3000/as/authorization.oauth2], request [<{scope=[accounts], grant_type=[authorization_code], client_id=[tpp1], client_secret=[2Federate], code=[i7pqEXYHrni2COCXbtjIz9yJ9m0Y7xyr8MAu5dgE], redirect_uri=[https://google.com]},[Content-Type:"application/x-www-form-urlencoded", Authorization:"Basic am9lOjJGZWRlcmF0ZQ=="]>]

            }
            else {
                LOGGER.info("exchanged the status [{}], response [{}]", response.getStatusCode(), response.getBody());
            }

            return "ABCDEF";

        } catch (Exception e) {
//            LOGGER.error("Error:", e);
//            throw new Exception("error to retrieve auth code");
            LOGGER.error("cannot get access token", e);
            return "ABCDEF12345";
        }

    }
}


