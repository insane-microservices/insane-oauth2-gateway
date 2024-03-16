package spring.io.fury.auth.security.oauth2;

import jakarta.ws.rs.BadRequestException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import spring.io.fury.auth.config.Oauth2ConfigProperties;
import spring.io.fury.auth.security.helpers.CookieUtils;

import java.net.URI;
import java.util.Optional;
import java.util.logging.Logger;

import static spring.io.fury.auth.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.ORIGIN_URI_PARAM_COOKIE_NAME;
import static spring.io.fury.auth.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository.REDIRECT_URI_PARAM_COOKIE_NAME;

@Component
@EnableConfigurationProperties(Oauth2ConfigProperties.class)
public class Oauth2AuthenticationSuccessHandler extends RedirectServerAuthenticationSuccessHandler {

    private final ServerOAuth2AuthorizedClientRepository repository;

    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    private final Logger logger = Logger.getLogger(Oauth2AuthenticationSuccessHandler.class.getName());

    private final Oauth2ConfigProperties oauth2ConfigProperties;


    @Autowired
    Oauth2AuthenticationSuccessHandler(HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository,
                                       ServerOAuth2AuthorizedClientRepository repository,
                                       Oauth2ConfigProperties oauth2ConfigProperties) {
        this.httpCookieOAuth2AuthorizationRequestRepository = httpCookieOAuth2AuthorizationRequestRepository;
        this.repository = repository;
        this.oauth2ConfigProperties = oauth2ConfigProperties;
    }

    @Override
    public Mono<Void> onAuthenticationSuccess(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
        ServerHttpResponse response = webFilterExchange.getExchange().getResponse();
        Mono<String> targetUrlMono = determineTargetUrl(webFilterExchange, authentication);

        if (response.isCommitted()) {
            return Mono.from(targetUrlMono).flatMap((targetUrl) -> {
                logger.info("Response has already been committed. Unable to redirect to " + targetUrl);
                return Mono.empty();
            });
        }
        return Mono.from(targetUrlMono).flatMap((targetUrl) -> {
            clearAuthenticationAttributes(request, response);
            super.setLocation(URI.create(targetUrl));
            return super.onAuthenticationSuccess(webFilterExchange, authentication);
        });
    }

    protected Mono<String> determineTargetUrl(WebFilterExchange webFilterExchange, Authentication authentication) {
        ServerHttpRequest request = webFilterExchange.getExchange().getRequest();
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        Optional<String> redirectUri = CookieUtils.getCookie(request, REDIRECT_URI_PARAM_COOKIE_NAME)
                .map(HttpCookie::getValue);
        Optional<String> originUri = CookieUtils.getCookie(request, ORIGIN_URI_PARAM_COOKIE_NAME).map(HttpCookie::getValue);

        if(redirectUri.isPresent() && !isAuthorizedRedirectUri(redirectUri.get())) {
            throw new BadRequestException("Sorry! We've got an Unauthorized Redirect URI and can't proceed with the authentication");
        }

        String targetUrl = redirectUri.orElse("");

        Mono<OAuth2AuthorizedClient> oAuth2AuthorizedClientMono = repository.loadAuthorizedClient(oauthToken.getAuthorizedClientRegistrationId(), authentication, webFilterExchange.getExchange());

        return Mono.from(oAuth2AuthorizedClientMono).map((oAuth2AuthorizedClient -> {
            OAuth2AccessToken accessToken = oAuth2AuthorizedClient.getAccessToken();


            OAuth2RefreshToken refreshToken = oAuth2AuthorizedClient.getRefreshToken();

            webFilterExchange.getExchange().getResponse().getHeaders().setBearerAuth(accessToken.getTokenValue());

            return UriComponentsBuilder.fromUriString(targetUrl)
                    .queryParam("access_token", accessToken.getTokenValue())
                    .queryParam("refresh_token", refreshToken.getTokenValue())
                    .queryParam("origin", originUri)
                    .build().toUriString();
        }));
    }

    protected void clearAuthenticationAttributes(ServerHttpRequest request, ServerHttpResponse response) {
        httpCookieOAuth2AuthorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }

    private boolean isAuthorizedRedirectUri(String uri) {
        return oauth2ConfigProperties.getAuthorizedRedirectUris().contains(uri);
    }
}

