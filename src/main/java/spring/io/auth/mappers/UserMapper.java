package spring.io.auth.mappers;

import org.mapstruct.Mapper;
import spring.io.auth.controllers.dtos.OAuth2UserDto;
import spring.io.auth.model.OAuth2User;

@Mapper(componentModel = "spring")
public abstract class UserMapper {
    public abstract OAuth2UserDto toOAuth2UserDto(OAuth2User oAuth2User);
    public abstract OAuth2User toOAuth2User(OAuth2UserDto oAuth2UserDto);
}
