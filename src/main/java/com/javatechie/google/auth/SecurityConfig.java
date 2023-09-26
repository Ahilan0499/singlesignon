package com.javatechie.google.auth;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimAccessor;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

@Configuration
//@EnableOAuth2Client
@EnableWebSecurity
@Import({KeycloakSecurityComponents.class, KeycloakSpringBootConfigResolver.class})
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.oauth2.client.registration.keycloak}")
    private String registrationId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-secret}")
    private String clientSecret;

    @Value("${spring.security.oauth2.client.registration.keycloak.client-name}")
    private String clientName;

    @Value("${spring.security.oauth2.client.registration.keycloak.scope}")
    private String scope;

    @Value("${spring.security.oauth2.client.registration.keycloak.redirect-uri-template}")
    private String redirectUriTemplate;

    @Value("${spring.security.oauth2.client.registration.keycloak.authorizationUri}")
    private String authorizationUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.tokenUri}")
    private String tokenUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.jwkSetUri}")
    private String jwkSetUri;

    @Value("${spring.security.oauth2.client.registration.keycloak.user-info-uri}")
    private String userInfoUri;


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.exceptionHandling().and().authorizeRequests().antMatchers("favicon-io", "/static-ons/**", "/sign-in")
                .permitAll().anyRequest().authenticated().and().logout().logoutUrl("/sign-out")
                .logoutSuccessUrl("").and().sessionManagement().maximumSessions(-1).expiredUrl("/?session=expired").and().invalidSessionUrl("/?session=invalid")
                .and().oauth2Login().loginPage("/index.html").defaultSuccessUrl("/message");
    }

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository{
        return new InMemoryClientRegistrationRepository(this.keycloakClientRegistration());
    }

    private ClientRegistration keycloakClientRegistration{
        ClientRegistration.Builder builder = ClientRegistration.withRegistrationId(registrationId).clientId(clientId)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).scope("email","openid","profile")
                .redirectUriTemplate(redirectUriTemplate).authorizationUri(authorizationUri).tokenUri(tokenUri)
                .jwkSetUri(jwkSetUri).userInfoUri(userInfoUri).userNameAttributeName(IdTokenClaimNames.SUB);
    }
        return builder.build();
}