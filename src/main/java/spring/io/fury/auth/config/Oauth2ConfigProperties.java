package spring.io.fury.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@ConfigurationProperties("app.oauth2")
@Getter
@Setter
public class Oauth2ConfigProperties {
    private List<String> authorizedRedirectUris;
}
