package spring.io.auth.controllers;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import spring.io.auth.controllers.dtos.OAuth2UserDto;
import spring.io.auth.mappers.UserMapper;
import spring.io.auth.model.OAuth2User;

@RestController
public class AuthController {
    private final UserMapper userMapper;

    @Autowired
    public AuthController(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @ResponseBody
    @GetMapping(path = "/oauth2/authorizedUser")
    public OAuth2UserDto userDetails(Authentication authentication) {
        OAuth2AuthenticatedPrincipal principal = (OAuth2AuthenticatedPrincipal) authentication.getPrincipal();
        return userMapper.toOAuth2UserDto(OAuth2User.createOAuth2User(principal));
    }
}
