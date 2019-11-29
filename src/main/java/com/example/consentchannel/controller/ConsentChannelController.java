package com.example.consentchannel.controller;

import com.example.consentchannel.config.CredentialContext;
import com.example.consentchannel.model.OpenBankingIntentId;
import com.example.consentchannel.model.RequestJwtClaims;
import com.example.consentchannel.model.RequestJwtClaimsWrapper;
import com.example.consentchannel.model.UserInfo;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
@RequestMapping(value = "/inet")
public class ConsentChannelController {

  private ObjectMapper objectMapper = new ObjectMapper();

  private final RestTemplate restTemplate;
  private final CredentialContext credentialContext;

  @Autowired
  public ConsentChannelController(RestTemplate restTemplate, CredentialContext credentialContext){
    this.restTemplate = restTemplate;
    this.credentialContext = credentialContext;
  }

//  @Autowired
//  private AccessService accessService;

  private static final Logger LOGGER = LoggerFactory.getLogger(ConsentChannelController.class);

  /**
   * security/v2/consents?correlation_id=5223927d-6cfe-4ecd-b73b-d8b0f0c54764
   * &query_string=client_id%253DSwCIxkpf8em1ZbS5CM7MRSh9PnheUNNd%2526scope%253Dopenid+accounts%2526redirect_uri%253Dhttp%253A%252F%252Flocalhost%253A8585%252FredirectMe%2526response_type%253Dcode+id_token%2526someOtherParam%253Dblahblah%2526request%253DeyJraWQiOiJzYW1wbGVUcHBLaWQiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6IlN3Q0l4a3BmOGVtMVpiUzVDTTdNUlNoOVBuaGVVTk5kIiwiYXVkIjoiaHR0cHM6Ly9haWItcHJvZC1wcm9kLmFwaWdlZS5uZXQiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyIsInN0YXRlIjoiOWU3MjY3NDgtYzExOS00NmRkLTg0ZGMtMjQxY2MzOWQ2ZDdjIiwibm9uY2UiOiJmNWNjYWQ1Zi0yMzdkLTQzNTYtYmNiNi0yM2M2YmZmMTBhNDUiLCJtYXhfYWdlIjoiODY0MDAwMCIsImlhdCI6MTU3NDk0MzcxNCwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4NTg1L3JlZGlyZWN0TWUiLCJjbGFpbXMiOnsidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6MTE3ZDU0NDMtNGVkNS00Njg5LWE5MjMtNjAxMDk4ZmYyNzQ0IiwiZXNzZW50aWFsIjp0cnVlfX0sImlkX3Rva2VuIjp7Im9wZW5iYW5raW5nX2ludGVudF9pZCI6eyJ2YWx1ZSI6InVybjphaWI6YXBpZ2F0ZXdheTpvcGVuLWJhbmtpbmc6YWlzcDphY2NvdW50LWFjY2Vzcy1jb25zZW50czp2My4xOjExN2Q1NDQzLTRlZDUtNDY4OS1hOTIzLTYwMTA5OGZmMjc0NCIsImVzc2VudGlhbCI6dHJ1ZX0sImFjciI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJ1cm46YWliOmFwaWdhdGV3YXk6b3Blbi1iYW5raW5nOmFpc3A6YWNjb3VudC1hY2Nlc3MtY29uc2VudHM6djMuMToxMTdkNTQ0My00ZWQ1LTQ2ODktYTkyMy02MDEwOThmZjI3NDQiXX19fSwiZXhwIjoxNTc0OTQ3MzE0fQ.FsCGyN3O5GQ2DtjIHDQgNrqi2av3rzu2LJsWj5ZhYE5bDvGvyacn89kIeCZToDXQKGX_4LvTRWcto4jXISI8voyyBL9Prb4TDynlgXpOJ1PIV5Xs9NbkWNnJRuLWgShzw_OlNruZlD3AR61KbN9SvxLTin3ds_0DVwZX1FS0PgBz33LqWffhhKal0V4FUTqD1FUKMP6Q-8WqeyHOhCMqUqVM3S32tfin7RMODzZeS75_FZxgr199i8BVllgGBMx4nnvVwEL1P3SAa49H5OF4cvbsGvoj5TUXua31c4z1ximxCkhwx2-JBoQHtQ91fGm3hknDFxfg8mNEBJ6cRVZhWQ%2526state%253D9e726748-c119-46dd-84dc-241cc39d6d7c%2526nonce%253Df5ccad5f-237d-4356-bcb6-23c6bff10a45
   */
  @PostMapping("security/v2/consents")
  public void initConsent(
      @PathVariable(name = "correlation_id") String correlationId,
      @PathVariable(name = "query_string") String queryString)  {

//    String request = extractQueryString(queryString, "request");
//    String request = "client_id%253DSwCIxkpf8em1ZbS5CM7MRSh9PnheUNNd%2526scope%253Dopenid+accounts%2526redirect_uri%253Dhttp%253A%252F%252Flocalhost%253A8585%252FredirectMe%2526response_type%253Dcode+id_token%2526someOtherParam%253Dblahblah%2526request%253DeyJraWQiOiJzYW1wbGVUcHBLaWQiLCJhbGciOiJSUzI1NiJ9.eyJyZXNwb25zZV90eXBlIjoiY29kZSBpZF90b2tlbiIsImNsaWVudF9pZCI6IlN3Q0l4a3BmOGVtMVpiUzVDTTdNUlNoOVBuaGVVTk5kIiwiYXVkIjoiaHR0cHM6Ly9haWItcHJvZC1wcm9kLmFwaWdlZS5uZXQiLCJzY29wZSI6Im9wZW5pZCBhY2NvdW50cyIsInN0YXRlIjoiOWU3MjY3NDgtYzExOS00NmRkLTg0ZGMtMjQxY2MzOWQ2ZDdjIiwibm9uY2UiOiJmNWNjYWQ1Zi0yMzdkLTQzNTYtYmNiNi0yM2M2YmZmMTBhNDUiLCJtYXhfYWdlIjoiODY0MDAwMCIsImlhdCI6MTU3NDk0MzcxNCwicmVkaXJlY3RfdXJpIjoiaHR0cDovL2xvY2FsaG9zdDo4NTg1L3JlZGlyZWN0TWUiLCJjbGFpbXMiOnsidXNlcmluZm8iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoidXJuOmFpYjphcGlnYXRld2F5Om9wZW4tYmFua2luZzphaXNwOmFjY291bnQtYWNjZXNzLWNvbnNlbnRzOnYzLjE6MTE3ZDU0NDMtNGVkNS00Njg5LWE5MjMtNjAxMDk4ZmYyNzQ0IiwiZXNzZW50aWFsIjp0cnVlfX0sImlkX3Rva2VuIjp7Im9wZW5iYW5raW5nX2ludGVudF9pZCI6eyJ2YWx1ZSI6InVybjphaWI6YXBpZ2F0ZXdheTpvcGVuLWJhbmtpbmc6YWlzcDphY2NvdW50LWFjY2Vzcy1jb25zZW50czp2My4xOjExN2Q1NDQzLTRlZDUtNDY4OS1hOTIzLTYwMTA5OGZmMjc0NCIsImVzc2VudGlhbCI6dHJ1ZX0sImFjciI6eyJlc3NlbnRpYWwiOnRydWUsInZhbHVlcyI6WyJ1cm46YWliOmFwaWdhdGV3YXk6b3Blbi1iYW5raW5nOmFpc3A6YWNjb3VudC1hY2Nlc3MtY29uc2VudHM6djMuMToxMTdkNTQ0My00ZWQ1LTQ2ODktYTkyMy02MDEwOThmZjI3NDQiXX19fSwiZXhwIjoxNTc0OTQ3MzE0fQ.FsCGyN3O5GQ2DtjIHDQgNrqi2av3rzu2LJsWj5ZhYE5bDvGvyacn89kIeCZToDXQKGX_4LvTRWcto4jXISI8voyyBL9Prb4TDynlgXpOJ1PIV5Xs9NbkWNnJRuLWgShzw_OlNruZlD3AR61KbN9SvxLTin3ds_0DVwZX1FS0PgBz33LqWffhhKal0V4FUTqD1FUKMP6Q-8WqeyHOhCMqUqVM3S32tfin7RMODzZeS75_FZxgr199i8BVllgGBMx4nnvVwEL1P3SAa49H5OF4cvbsGvoj5TUXua31c4z1ximxCkhwx2-JBoQHtQ91fGm3hknDFxfg8mNEBJ6cRVZhWQ%2526state%253D9e726748-c119-46dd-84dc-241cc39d6d7c%2526nonce%253Df5ccad5f-237d-4356-bcb6-23c6bff10a45"

    try {
      String consentId = extractConsentId(queryString);
      String accessToken = null;
      accessToken = generateAccessTokenForAccountRequest();
    } catch (Exception e) {
      e.printStackTrace();
    }
    HttpHeaders headers = buildHeaders(accessToken);
    URI getConsentUri = UriComponentsBuilder
            .fromHttpUrl(apigeeConfig.getApigeeConsentsUrl() + "/" + consentId)
            .build()
            .toUri();
    restTemplate.

    LOGGER.info("correlation_id [{}] and query_string [{}]", correlationId, queryString);
  }

  protected String extractQueryString(String queryString, String extractKey)
          throws MalformedURLException, UnsupportedEncodingException {

    String decodedRequest ="?" + queryString.replaceAll("%253D", "=").replaceAll("\\+", " ")
            .replaceAll("%2526", "&");
    URL url = new URL("http", "localhost", decodedRequest);
    Map<String, String> queryPairs = new LinkedHashMap<>();
    String query = url.getQuery();
    String[] pairs = query.split("&");
    for (String pair : pairs) {
      int idx = pair.indexOf("=");
      queryPairs.put(
              URLDecoder.decode(pair.substring(0, idx), "UTF-8"), URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
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
      RequestJwtClaimsWrapper requestJwtClaimsWrapper = objectMapper.readValue(rawJson, RequestJwtClaimsWrapper.class);
      System.out.println("requestJwtClaimsWrapper: " + requestJwtClaimsWrapper);

      return requestJwtClaimsWrapper.getRequestJwtClaims().getIdToken().getOpenBankingIntentId().getValue();


    } catch (InvalidJwtException e) {
      System.err.println("Internal user JWT invalid! " + e);
      throw new Exception("Internal user JWT invalid");
    } catch (Exception e){
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

  private String generateAccessTokenForAccountRequest() throws Exception {

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

      if (!org.springframework.util.StringUtils.isEmpty(scope)) {
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
  private HttpHeaders buildHeaders(String accessToken) {

    HttpHeaders headers = buildHeaders(false);

    String authorization = new StringBuilder("Bearer ").append(accessToken).toString();
    headers.add("Authorization", authorization);
    headers.add(FAPI_FINANCIAL_ID_HEADER, FAPI_FINANCIAL_ID);
    headers.add(FAPI_INTERACTION_ID_HEADER, UUID.randomUUID().toString());
    headers.add("x-idempotency-key",
            Long.toString(DateTime.now().toDate().getTime()));

    return headers;
  }
}
