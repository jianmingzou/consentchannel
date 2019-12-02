package com.example.consentchannel.configuration;


import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.client.ClientHttpRequestFactorySupplier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

@Configuration
@EnableConfigurationProperties(CredentialContext.class)
public class ConsentChannelConfig {


  @Bean
  RestTemplate restTemplate() {

//    RestTemplateBuilder builder = new RestTemplateBuilder();

//    List<HttpMessageConverter<?>> httpMessageConverters = new ArrayList<>();
//    httpMessageConverters.add(new FormHttpMessageConverter());
//    httpMessageConverters.add(new StringHttpMessageConverter());

    /*
     * Create a RestTemplate that uses a request factory that references
     * our custom HttpClient
     */
//    return builder.additionalMessageConverters(httpMessageConverters).
//            requestFactory(new ClientHttpRequestFactorySupplier()).build();

    return new RestTemplate();
  }



}
