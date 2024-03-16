package spring.io.fury.auth.security.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.DefaultServerRedirectStrategy;
import org.springframework.security.web.server.ServerRedirectStrategy;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.ServerAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import spring.io.fury.auth.security.helpers.CookieUtils;

import java.net.URI;

import static spring.io.fury.auth.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
public class OAuth2AuthenticationFailureHandler implements ServerAuthenticationFailureHandler {
    private final ServerRedirectStrategy redirectStrategy = new DefaultServerRedirectStrategy();

    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    @Autowired
    public OAuth2AuthenticationFailureHandler(HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository) {
        this.authorizationRequestRepository = authorizationRequestRepository;
    }

    @Override
    public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
        ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
        String targetUrl = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
            .map(HttpCookie::getValue)
            .orElse(("/"));

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
        return this.redirectStrategy.sendRedirect(webFilterExchange.getExchange(), URI.create(targetUrl));
    }
}
