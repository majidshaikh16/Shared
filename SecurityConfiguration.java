import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;

@Slf4j
@EnableWebSecurity
@Configuration
@Profile("!test")
public class SecurityConfiguration {

    @Value("${security.oauth2.resource.jwt.key-uri}")
    private String keyUri;

    @Value("${api.resourceUri}")
    private String resourceUri;

    @Value("${security.oauth2.access.issuer}")
    private String accessIssuer;

    private final APIRoleAccessDetails apiRoleAccessDetails;

    public SecurityConfiguration(APIRoleAccessDetails apiRoleAccessDetails) {
        this.apiRoleAccessDetails = apiRoleAccessDetails;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> {
                for (APIRoleMapping mapping : apiRoleAccessDetails.getRoles()) {
                    if (mapping.getRole() != null && mapping.getUrlPatterns() != null) {
                        auth.requestMatchers(mapping.getUrlPatterns().toArray(new String[0]))
                            .hasAuthority(mapping.getRole());
                    }
                }

                if (!apiRoleAccessDetails.getPermitAll().getUrlPatterns().isEmpty()) {
                    auth.requestMatchers(apiRoleAccessDetails.getPermitAll().getUrlPatterns().toArray(new String[0]))
                        .permitAll();
                }

                auth.anyRequest().authenticated();
            })
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt
                .decoder(jwtDecoder())
                .jwtAuthenticationConverter(jwtAuthenticationConverter())
            ));

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() throws MalformedURLException {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(keyUri).build();

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceClaimValidator(resourceUri);
        OAuth2TokenValidator<Jwt> issuerValidator = JwtValidators.createDefaultWithIssuer(accessIssuer);

        OAuth2TokenValidator<Jwt> combinedValidator =
            new DelegatingOAuth2TokenValidator<>(issuerValidator, audienceValidator);

        jwtDecoder.setJwtValidator(combinedValidator);
        return jwtDecoder;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthorityPrefix(""); // Optional: remove "SCOPE_" prefix
        authoritiesConverter.setAuthoritiesClaimName("scope"); // Adjust if needed

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

    // Your upgraded audience claim validator
    public static class AudienceClaimValidator implements OAuth2TokenValidator<Jwt> {

        private final String requiredAudience;

        public AudienceClaimValidator(String requiredAudience) {
            this.requiredAudience = requiredAudience;
        }

        @Override
        public OAuth2TokenValidatorResult validate(Jwt jwt) {
            List<String> audiences = jwt.getAudience();
            if (audiences.contains(requiredAudience)) {
                return OAuth2TokenValidatorResult.success();
            }
            OAuth2Error error = new OAuth2Error("invalid_token", "Invalid audience: " + requiredAudience, null);
            return OAuth2TokenValidatorResult.failure(error);
        }
    }
}
