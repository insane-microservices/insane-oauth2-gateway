package spring.io.fury.auth.security.oauth2;

import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import spring.io.fury.auth.security.helpers.CookieUtils;

import java.util.Map;
import java.util.Objects;

@Component
public class HttpCookieOAuth2AuthorizationRequestRepository implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";
    public static final String REDIRECT_URI_PARAM_COOKIE_NAME = "redirect_uri";
    public static final String ORIGIN_URI_PARAM_COOKIE_NAME = "origin";
    private static final int cookieExpireSeconds = 180;

    public void removeAuthorizationRequestCookies(ServerHttpRequest request, ServerHttpResponse response) {
        CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
        CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange serverWebExchange) {
        return Mono.just(Objects.requireNonNull(CookieUtils.getCookie(serverWebExchange.getRequest(), OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(cookie -> CookieUtils.deserialize(cookie, OAuth2AuthorizationRequest.class))
                .orElse(null)));
    }

    @Override
    public Mono<Void> saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange serverWebExchange) {
        ServerHttpRequest request = serverWebExchange.getRequest();
        ServerHttpResponse response = serverWebExchange.getResponse();
        if (authorizationRequest == null) {
            CookieUtils.deleteCookie(request, response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME);
            CookieUtils.deleteCookie(request, response, REDIRECT_URI_PARAM_COOKIE_NAME);
            return Mono.empty();
        }
        CookieUtils.addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, CookieUtils.serialize(authorizationRequest), cookieExpireSeconds);
        Map<String, String> map = request.getQueryParams().toSingleValueMap();
        String redirectUriAfterLogin =  map.getOrDefault(REDIRECT_URI_PARAM_COOKIE_NAME, "");
        String originUriAfterLogin = map.getOrDefault(ORIGIN_URI_PARAM_COOKIE_NAME, "");
        if (StringUtils.isNotBlank(redirectUriAfterLogin)) {
            CookieUtils.addCookie(response, REDIRECT_URI_PARAM_COOKIE_NAME, redirectUriAfterLogin, cookieExpireSeconds);
        }
        if (StringUtils.isNotBlank(originUriAfterLogin)) {
            CookieUtils.addCookie(response, ORIGIN_URI_PARAM_COOKIE_NAME, originUriAfterLogin, cookieExpireSeconds);
        }
        return Mono.empty();
    }

    @Override
    public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange serverWebExchange) {
        return this.loadAuthorizationRequest(serverWebExchange);
    }
}
