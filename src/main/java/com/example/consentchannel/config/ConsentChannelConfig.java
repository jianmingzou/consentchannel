package com.example.consentchannel.config;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.ClientHttpRequestFactorySupplier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ConsentChannelConfig {

  private static final String keystorePass = "password";

  @Value("classpath:keystore.jks")
  private Resource keystore;

  @Value("classpath:truststore.jks")
  private Resource truststore;

  @Bean
  public HttpComponentsClientHttpRequestFactory httpComponentsClientHttpRequestFactory()
      throws Exception {
    PoolingHttpClientConnectionManager poolingConnectionManager =
        new PoolingHttpClientConnectionManager();
    poolingConnectionManager.setMaxTotal(10000);
    poolingConnectionManager.setDefaultMaxPerRoute(20);
    /*
     * Create an SSLContext that uses client.jks as the client certificate
     * and the truststore.jks as the trust material (trusted CA certificates).
     * In this sample, truststore.jks contains ca.pem which was used to sign
     * both client.pfx and server.jks.
     */

    SSLContext sslContext = createSslContext();
    CloseableHttpClient client =
        HttpClientBuilder.create()
            .setSSLContext(sslContext)
            .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
            .setConnectionManager(poolingConnectionManager)
            .build();

    HttpComponentsClientHttpRequestFactory clientHttpRequestFactory =
        new HttpComponentsClientHttpRequestFactory(client);
    clientHttpRequestFactory.setConnectTimeout(10000);
    clientHttpRequestFactory.setReadTimeout(60000);
    return clientHttpRequestFactory;
  }


  @Bean
  public RestTemplate buildRemoteRestTemplate() throws Exception {

    RestTemplateBuilder builder = new RestTemplateBuilder();

    List<HttpMessageConverter<?>> httpMessageConverters = new ArrayList<>();
    httpMessageConverters.add(new FormHttpMessageConverter());
    httpMessageConverters.add(new StringHttpMessageConverter());

    /*
     * Create a RestTemplate that uses a request factory that references
     * our custom HttpClient
     */
    return builder.additionalMessageConverters(httpMessageConverters).
            requestFactory(new ClientHttpRequestFactorySupplier()).build();
  }

  @Bean
  public SSLContext createSslContext() throws Exception {

    SSLContextBuilder sslContextBuilder =
        SSLContexts.custom()
            .loadKeyMaterial(getStore(keystore, keystorePass), keystorePass.toCharArray());

    if (truststore != null) {
      KeyStore keyStore = getStore(truststore, keystorePass);
      sslContextBuilder.loadTrustMaterial(keyStore, new TrustSelfSignedStrategy());
    }

    return sslContextBuilder.build();
  }

  private KeyStore getStore(Resource keystore, String password) throws Exception {

    KeyStore keyStore = KeyStore.getInstance("JKS");
    try (InputStream in = keystore.getInputStream()) {
      keyStore.load(in, password.toCharArray());
    }
    return keyStore;
  }


}
