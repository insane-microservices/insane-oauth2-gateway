package spring.io.fury.auth.security.helpers;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.SerializationUtils;

import java.util.Base64;
import java.util.Map;
import java.util.Optional;

public class CookieUtils {

    public static Optional<HttpCookie> getCookie(ServerHttpRequest request, String name) {
        Map<String, HttpCookie> cookies = request.getCookies().toSingleValueMap();

        if (!cookies.isEmpty()) {
            HttpCookie cookie = cookies.get(name);
            return Optional.of(cookie);
        }

        return Optional.empty();
    }

    public static void addCookie(ServerHttpResponse response, String name, String value, int maxAge) {
        ResponseCookie cookie = ResponseCookie.fromClientResponse(name, value).httpOnly(true).maxAge(maxAge).path("/").build();
        response.addCookie(cookie);
    }

    public static void deleteCookie(ServerHttpRequest request, ServerHttpResponse response, String name) {
        Map<String, HttpCookie> cookies = request.getCookies().toSingleValueMap();
        if (!cookies.isEmpty()) {
            HttpCookie cookie = cookies.get(name);
            if (cookie != null) {
                ResponseCookie responseCookie = ResponseCookie.fromClientResponse(name, "")
                        .maxAge(0)
                        .path("/")
                        .build();
                response.addCookie(responseCookie);
            }
        }
    }

    public static String serialize(OAuth2AuthorizationRequest object) {
        return Base64.getUrlEncoder()
                .encodeToString(SerializationUtils.serialize(object));
    }

    public static <T> T deserialize(HttpCookie cookie, Class<T> cls) {
        return cls.cast(SerializationUtils.deserialize(
                        Base64.getUrlDecoder().decode(cookie.getValue())));
    }


}
