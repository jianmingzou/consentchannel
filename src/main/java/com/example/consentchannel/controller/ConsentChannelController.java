package com.example.consentchannel.controller;

import com.example.consentchannel.configuration.CredentialContext;
import com.example.consentchannel.model.ConsentAuthorisationResponse;
import com.example.consentchannel.model.OpenBankingIntentId;
import com.example.consentchannel.model.RequestJwtClaims;
import com.example.consentchannel.model.RequestJwtClaimsWrapper;
import com.example.consentchannel.model.UserInfo;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.websocket.server.PathParam;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
public class ConsentChannelController {


    private final ObjectMapper objectMapper;

    private final RestTemplate restTemplate = new RestTemplate();
    private final CredentialContext credentialContext;

    @Autowired
    public ConsentChannelController(
//            RestTemplate restTemplate,
            CredentialContext credentialContext,
            ObjectMapper objectMapper) {
//        this.restTemplate = restTemplate;
        this.credentialContext = credentialContext;
        this.objectMapper = objectMapper;
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ConsentChannelController.class);

    /**
     * security/v2/consents?correlation_id=5223927d-6cfe-4ecd-b73b-d8b0f0c54764 &query_string=client_id%253DSwCIxkpf8em1ZbS5CM7MRSh9PnheUNNd%2526scope%253Dopenid+accounts%2526redirect_uri%253Dhttp%253A%252F%252Flocalhost%253A8585%252FredirectMe%2526response_type%253Dcode+id_token%2526someOtherParam%253Dblahblah%2526request%253DeyJraWQiOiJzYW1wbGVUcHBLaWQiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6IlN3Q0l4a3BmOGVtMVpiUzVDTTdNUlNoOVBuaGVVTk5kIiwiYXVkIjoiaHR0cHM6Ly9haWItcHJvZC1wcm9kLmFwaWdlZS5uZXQiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyIsInN0YXRlIjoiOWU3MjY3NDgtYzExOS00NmRkLTg0ZGMtMjQxY2MzOWQ2ZDdjIiwibm9uY2UiOiJmNWNjYWQ1Zi0yMzdkLTQzNTYtYmNiNi0yM2M2YmZmMTBhNDUiLCJtYXhfYWdlIjoiODY0MDAwMCIsImlhdCI6MTU3NDk0MzcxNCwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4NTg1L3JlZGlyZWN0TWUiLCJjbGFpbXMiOnsidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6MTE3ZDU0NDMtNGVkNS00Njg5LWE5MjMtNjAxMDk4ZmYyNzQ0IiwiZXNzZW50aWFsIjp0cnVlfX0sImlkX3Rva2VuIjp7Im9wZW5iYW5raW5nX2ludGVudF9pZCI6eyJ2YWx1ZSI6InVybjphaWI6YXBpZ2F0ZXdheTpvcGVuLWJhbmtpbmc6YWlzcDphY2NvdW50LWFjY2Vzcy1jb25zZW50czp2My4xOjExN2Q1NDQzLTRlZDUtNDY4OS1hOTIzLTYwMTA5OGZmMjc0NCIsImVzc2VudGlhbCI6dHJ1ZX0sImFjciI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJ1cm46YWliOmFwaWdhdGV3YXk6b3Blbi1iYW5raW5nOmFpc3A6YWNjb3VudC1hY2Nlc3MtY29uc2VudHM6djMuMToxMTdkNTQ0My00ZWQ1LTQ2ODktYTkyMy02MDEwOThmZjI3NDQiXX19fSwiZXhwIjoxNTc0OTQ3MzE0fQ.FsCGyN3O5GQ2DtjIHDQgNrqi2av3rzu2LJsWj5ZhYE5bDvGvyacn89kIeCZToDXQKGX_4LvTRWcto4jXISI8voyyBL9Prb4TDynlgXpOJ1PIV5Xs9NbkWNnJRuLWgShzw_OlNruZlD3AR61KbN9SvxLTin3ds_0DVwZX1FS0PgBz33LqWffhhKal0V4FUTqD1FUKMP6Q-8WqeyHOhCMqUqVM3S32tfin7RMODzZeS75_FZxgr199i8BVllgGBMx4nnvVwEL1P3SAa49H5OF4cvbsGvoj5TUXua31c4z1ximxCkhwx2-JBoQHtQ91fGm3hknDFxfg8mNEBJ6cRVZhWQ%2526state%253D9e726748-c119-46dd-84dc-241cc39d6d7c%2526nonce%253Df5ccad5f-237d-4356-bcb6-23c6bff10a45
     */
    @PostMapping("/consent/auth")
    @ResponseBody
    public ResponseEntity<?> initConsent(
            @RequestParam( "correlation_id") String correlationId,
//            @RequestParam("query_string") String queryString,
            @RequestParam("intent_id") String intentId){

//    String request = extractQueryString(queryString, "request");
    String queryString = "client_id%253DSwCIxkpf8em1ZbS5CM7MRSh9PnheUNNd%2526scope%253Dopenid+accounts%2526redirect_uri%253Dhttp%253A%252F%252Flocalhost%253A8585%252FredirectMe%2526response_type%253Dcode+id_token%2526someOtherParam%253Dblahblah%2526request%253DeyJraWQiOiJzYW1wbGVUcHBLaWQiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6IlN3Q0l4a3BmOGVtMVpiUzVDTTdNUlNoOVBuaGVVTk5kIiwiYXVkIjoiaHR0cHM6Ly9haWItcHJvZC1wcm9kLmFwaWdlZS5uZXQiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyIsInN0YXRlIjoiOWU3MjY3NDgtYzExOS00NmRkLTg0ZGMtMjQxY2MzOWQ2ZDdjIiwibm9uY2UiOiJmNWNjYWQ1Zi0yMzdkLTQzNTYtYmNiNi0yM2M2YmZmMTBhNDUiLCJtYXhfYWdlIjoiODY0MDAwMCIsImlhdCI6MTU3NDk0MzcxNCwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4NTg1L3JlZGlyZWN0TWUiLCJjbGFpbXMiOnsidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6MTE3ZDU0NDMtNGVkNS00Njg5LWE5MjMtNjAxMDk4ZmYyNzQ0IiwiZXNzZW50aWFsIjp0cnVlfX0sImlkX3Rva2VuIjp7Im9wZW5iYW5raW5nX2ludGVudF9pZCI6eyJ2YWx1ZSI6InVybjphaWI6YXBpZ2F0ZXdheTpvcGVuLWJhbmtpbmc6YWlzcDphY2NvdW50LWFjY2Vzcy1jb25zZW50czp2My4xOjExN2Q1NDQzLTRlZDUtNDY4OS1hOTIzLTYwMTA5OGZmMjc0NCIsImVzc2VudGlhbCI6dHJ1ZX0sImFjciI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJ1cm46YWliOmFwaWdhdGV3YXk6b3Blbi1iYW5raW5nOmFpc3A6YWNjb3VudC1hY2Nlc3MtY29uc2VudHM6djMuMToxMTdkNTQ0My00ZWQ1LTQ2ODktYTkyMy02MDEwOThmZjI3NDQiXX19fSwiZXhwIjoxNTc0OTQ3MzE0fQ.FsCGyN3O5GQ2DtjIHDQgNrqi2av3rzu2LJsWj5ZhYE5bDvGvyacn89kIeCZToDXQKGX_4LvTRWcto4jXISI8voyyBL9Prb4TDynlgXpOJ1PIV5Xs9NbkWNnJRuLWgShzw_OlNruZlD3AR61KbN9SvxLTin3ds_0DVwZX1FS0PgBz33LqWffhhKal0V4FUTqD1FUKMP6Q-8WqeyHOhCMqUqVM3S32tfin7RMODzZeS75_FZxgr199i8BVllgGBMx4nnvVwEL1P3SAa49H5OF4cvbsGvoj5TUXua31c4z1ximxCkhwx2-JBoQHtQ91fGm3hknDFxfg8mNEBJ6cRVZhWQ%2526state%253D9e726748-c119-46dd-84dc-241cc39d6d7c%2526nonce%253Df5ccad5f-237d-4356-bcb6-23c6bff10a45";
        LOGGER.info("correlation_id [{}] and query_string [{}], intent id [{}]", correlationId, queryString, intentId);

        try {
            validateConsent(extractConsentId(extractQueryString(queryString,"request")));
            StringBuilder stringBuilder = new StringBuilder();
//            {"redirect_uri": "http://localhost:8585/redirectMe#code=HrvkTgAi&scope=accounts&state=40ef40a6-c1e6-433a-8587-0129e4aed07c&id_token=eyJ0eXAiOiJKV1QiLCJraWQiOiJhaWItc2lnbmVyLXNhbXBsZS12MS1ST0kiLCJhbGciOiJQUzI1NiJ9.eyJpc3MiOiJodHRwczovL2FwaS1zaXQtaW50ZXJuYWwuYWlidGVzdC5pZSIsImF1ZCI6IlZVRGtWUHNKeVlDWHZxWnRzTENFS3pkNlpVYVVyU2xmIiwic3ViIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6NWM2YTI2YjctMmQyMi00Zjc5LWFmY2ItM2NiZDdiYjFjYTdhIiwib3BlbmJhbmtpbmdfaW50ZW50X2lkIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6NWM2YTI2YjctMmQyMi00Zjc5LWFmY2ItM2NiZDdiYjFjYTdhIiwiYWNyIjoidXJuOm9wZW5iYW5raW5nOnBzZDI6c2NhIiwiZXhwIjoxNTc1MDIxNjMwLCJpYXQiOjE1NzUwMjEzMzAsIm5vbmNlIjoiN2FmN2NiYWItMzc3NS00NTUxLTg2MDQtNjU5ZmIyYjFmNjM1Iiwic19oYXNoIjoibFZESjRocGlVVFVhakN5WDlyVkZmQSIsImNfaGFzaCI6IkRQM2tZOXhJWjJOREZ1UVZrb0JNRWcifQ.oVTePpMBkmvxQxAByHsxqx13MkHJWPMBZdMkJgnwuCZSgIbOfKRKv5HHTqpusYap-dsCyfJIXBKZ5AXMNAtWnwpFT_AeIW3POetvukt05FWS_Sd6m-kUMiiGvZwZD2RfzYHgcuYCoYfxt4Ntd-eU8W_sz1YwwDtPBWUEBfHp8bOnzAKPI2gBWr1AMEL-miMv1d21lEWBPNVaKxuTY4Sw_wKf2rfvvM9BXszDTiKef-nuqLHxdDOCmfOrc3luSzNaWIj7rHtalJnyqPzic2oes6zK1pWsJB9q1VaDCQMbv7a9ExhgHcyxHXcWKwkA18dUUiZ8cPpsR6i1M-8hzh0jZw"}
            stringBuilder.append(extractQueryString(queryString, "redirect_uri")).append("?scope=accounts");
            stringBuilder.append("code=").append(authorizationCode());
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

        String decodedRequest = "?" + queryString.replaceAll("%253D", "=").replaceAll("\\+", " ")
                .replaceAll("%2526", "&");
        LOGGER.info("decoded request: [{}]", decodedRequest);
        URL url = new URL("http", "localhost", decodedRequest);
        Map<String, String> queryPairs = new LinkedHashMap<>();
        String query = url.getQuery();
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            queryPairs.put(
                    URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                    URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
        }
        System.out.println(queryPairs);

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
            System.err.println("Internal user JWT invalid! " + e);
            throw new Exception("Internal user JWT invalid");
        } catch (Exception e) {
            System.err.println("claim allowed_accounts is invalid " + e);
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

//        idTokenOpenBankingIntentId = extractOpenBankingIntentId(requestJwtClaims.getIdToken());
            }
        }

//    if (StringUtils.isBlank(userInfoOpenBankingIntentId) && StringUtils.isBlank(idTokenOpenBankingIntentId)) {
//      throw newErrorMessageException(PROXYCONSENT_ERROR_MISSING_OB_INTENT_ID, consentExecutionRequest.getRedirectUri(), consentExecutionRequest.getState(), consentExecutionRequest);
//    }

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





    private void validateConsent(String consentId) throws  Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getConsentMgtUri() + "/" + consentId);

        URI consentInitiationUri = uriComponentsBuilder.build().toUri();
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<JsonNode> request = new HttpEntity<>(headers);

        try {

            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(consentInitiationUri, HttpMethod.GET, request, JsonNode.class);

            if(response.getStatusCode().is2xxSuccessful()){
                LOGGER.info("found the consent in consent management");
            }

        } catch (HttpStatusCodeException e) {
            LOGGER.error("Error:", e);
        }

    }

    private String authorizationCode() throws  Exception {

        UriComponentsBuilder uriComponentsBuilder =
                UriComponentsBuilder.fromHttpUrl(credentialContext.getOauthUri());

        URI authCodeURI = uriComponentsBuilder.build().toUri();
        HttpHeaders headers = new HttpHeaders();
        HttpEntity<JsonNode> request = new HttpEntity<>(headers);

        try {

            ResponseEntity<JsonNode> response =
                    restTemplate.exchange(authCodeURI, HttpMethod.GET, request, JsonNode.class);


            if(response.getStatusCode().is2xxSuccessful()){
                LOGGER.info("found the consent in consent management");
            }

            return "XXXX";

        } catch (HttpStatusCodeException e) {
            LOGGER.error("Error:", e);
            return null;
        }

    }

}
