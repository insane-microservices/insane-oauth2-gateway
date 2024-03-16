package spring.io.fury.auth.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.client.RestTemplate;
import spring.io.fury.auth.controllers.dtos.OAuth2UserDto;
import spring.io.fury.auth.mappers.UserMapper;
import spring.io.fury.auth.model.OAuth2User;

//@RestController
public class AuthController {
    private final UserMapper userMapper;
    private RestTemplate restTemplate;

    @Autowired
    public AuthController(UserMapper userMapper, RestTemplate restTemplate) {
        this.userMapper = userMapper;
        this.restTemplate = restTemplate;
    }

    @ResponseBody
    @GetMapping(path = "/oauth2/authorizedUser")
    public OAuth2UserDto userDetails(Authentication authentication) {
        OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal) authentication.getPrincipal();
        //restTemplate.exchange("")
        return userMapper.toOAuth2UserDto(OAuth2User.createOAuth2User(principal));
    }
}
