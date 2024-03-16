package spring.io.fury.auth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;
import spring.io.fury.auth.security.oauth2.Oauth2AuthenticationSuccessHandler;
import spring.io.fury.auth.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import spring.io.fury.auth.security.oauth2.OAuth2AuthenticationFailureHandler;

import java.util.Collections;
import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    Oauth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;
    OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Autowired
    public SecurityConfig(Oauth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler, OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler) {
        this.oauth2AuthenticationSuccessHandler = oauth2AuthenticationSuccessHandler;
        this.oAuth2AuthenticationFailureHandler = oAuth2AuthenticationFailureHandler;
    }

    @Bean
    protected SecurityWebFilterChain getSecurityFilterChain(ServerHttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable()
                .formLogin().disable()
                .httpBasic().disable()
                .cors().configurationSource(corsConfigurationSource()).and()
                .exceptionHandling().authenticationEntryPoint(getAuthenticationEntryPoint())
                .and()
                .authorizeExchange(exchange ->
                    exchange.pathMatchers("/login", "/error", "/login/oauth2/code/keycloak*", "/oauth2/authorization/keycloak", "/eureka/**", "/static/favicon.ico")
                            .permitAll()
                            .anyExchange()
                            .authenticated()
                );
        httpSecurity.oauth2ResourceServer().opaqueToken();
        httpSecurity.oauth2Login(oauth2 ->
                        oauth2.
                                authorizationRequestRepository(getAuthReqRepository())
                                .authenticationSuccessHandler(oauth2AuthenticationSuccessHandler)
                                .authenticationFailureHandler(oAuth2AuthenticationFailureHandler));
        httpSecurity.logout();
        return httpSecurity.build();
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public WebSessionManager webSessionManager() {
        // Emulate SessionCreationPolicy.STATELESS
        return exchange -> Mono.empty();
    }

    @Bean
    public ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> getAuthReqRepository() {
        return new HttpCookieOAuth2AuthorizationRequestRepository();
    }

    @Bean
    public ServerAuthenticationEntryPoint getAuthenticationEntryPoint() {
        return new RestAuthenticationEntryPoint();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedMethods( Collections.singletonList( "*" ) );
        config.setAllowedOrigins( Collections.singletonList( "*" ) );
        config.setAllowedHeaders( Collections.singletonList( "*" ) );
        config.setAllowedMethods(List.of("GET", "POST", "DELETE", "PUT", "OPTIONS"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration( "/**", config );
        return source;
    }
}
