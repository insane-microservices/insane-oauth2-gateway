package spring.io.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class AuthResourceServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(AuthResourceServerApplication.class, args);
    }
}
