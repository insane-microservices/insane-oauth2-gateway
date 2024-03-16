package spring.io.fury.auth.controllers.dtos;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class OAuth2UserDto {
    String userName;
    String email;
    String givenName;
    String familyName;
}
