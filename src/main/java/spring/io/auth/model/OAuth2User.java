package spring.io.auth.model;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class OAuth2User implements OAuth2AuthenticatedPrincipal {
    private String userName;
    private String givenName;
    private String familyName;
    private String email;
    private Map<String, Object> attributes;
    private List<GrantedAuthority> authorities;

    public static OAuth2User createOAuth2User(OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal) {
        return new OAuth2User(
                oAuth2AuthenticatedPrincipal.getAttribute("username"),
                oAuth2AuthenticatedPrincipal.getAttribute("given_name"),
                oAuth2AuthenticatedPrincipal.getAttribute("family_name"),
                oAuth2AuthenticatedPrincipal.getAttribute("email"),
                oAuth2AuthenticatedPrincipal.getAttributes(),
                List.copyOf(oAuth2AuthenticatedPrincipal.getAuthorities())
        );
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getName() {
        return this.getAttribute("given_name");
    }

    public String getUserName() {
        return this.getAttribute("username");
    }

    public String getGivenName() {
        return this.getAttribute("given_name");
    }

    public String getFamilyName() {
        return this.getAttribute("family_name");
    }

    public String getEmail() {
        return this.getAttribute("email");
    }
}
