package spring.io.auth.config;

import org.springframework.web.client.RestTemplate;

public class AppConfig {
    public RestTemplate getRestTemplate() {
        return new RestTemplate();
    }
}
