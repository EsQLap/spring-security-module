package ru.virgil.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import ru.virgil.security.entity.AuthMethods;
import ru.virgil.security.firebase.FirebaseAuthenticationFilter;
import ru.virgil.security.firebase.FirebaseAuthorizationProvider;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;


@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public static final Map<AuthMethods, String> AUTH_API_PATHS = Map.of(
            AuthMethods.FIREBASE, "/auth/firebase"
    );
    public static final Map<AuthMethods, String> AUTH_PAGE_PATHS = Map.of(
            AuthMethods.FIREBASE, "/auth/firebase/page/**"
    );
    private final FirebaseAuthorizationProvider firebaseAuthorizationProvider;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final SecurityProperties securityProperties;

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        String[] propertyIgnoredPaths = Optional.ofNullable(securityProperties.anonymousPaths()).orElse(new String[0]);
        httpSecurity
                // todo: стандартный редирект на страницу успешной безопасности
                // todo: разобраться, как включить
                .cors()
                .and()
                .csrf().disable()
                .authorizeRequests()
                .mvcMatchers(AUTH_PAGE_PATHS.values().toArray(String[]::new)).permitAll()
                .mvcMatchers("/", "/favicon.ico", "/error").permitAll()
                .mvcMatchers(propertyIgnoredPaths).permitAll()
                .mvcMatchers("/**").authenticated()
                .and()
                .addFilterBefore(new FirebaseAuthenticationFilter(authenticationManager()),
                        UsernamePasswordAuthenticationFilter.class)
                .authenticationProvider(firebaseAuthorizationProvider)
        // todo: разобраться, как лучше реагировать на ошибки и не подставлять безопасность
        // .exceptionHandling()
        // .authenticationEntryPoint(authenticationEntryPoint)
        ;
    }

    @Bean
    protected CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration authCorsConfiguration = buildAuthCorsConfiguration();
        CorsConfiguration resultCorsConfiguration = buildResultCorsConfiguration();
        UrlBasedCorsConfigurationSource configurationSource = new UrlBasedCorsConfigurationSource();
        configurationSource.registerCorsConfiguration(AUTH_API_PATHS.get(AuthMethods.FIREBASE), authCorsConfiguration);
        configurationSource.registerCorsConfiguration("/**", resultCorsConfiguration);
        return configurationSource;
    }

    private CorsConfiguration buildResultCorsConfiguration() {
        CorsConfiguration resultCorsConfiguration = new CorsConfiguration();
        resultCorsConfiguration.setAllowedOrigins(List.of("http://localhost:4200"));
        resultCorsConfiguration.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION, HttpHeaders.COOKIE));
        resultCorsConfiguration.setAllowedMethods(Arrays.stream(HttpMethod.values()).map(Enum::name).toList());
        resultCorsConfiguration.setAllowCredentials(true);
        return resultCorsConfiguration;
    }

    private CorsConfiguration buildAuthCorsConfiguration() {
        CorsConfiguration authCorsConfiguration = new CorsConfiguration();
        authCorsConfiguration.setAllowedOrigins(List.of("http://localhost:4200"));
        authCorsConfiguration.setAllowedMethods(List.of(HttpMethod.POST.name()));
        authCorsConfiguration.setAllowedHeaders(List.of(HttpHeaders.AUTHORIZATION));
        authCorsConfiguration.setExposedHeaders(List.of(HttpHeaders.AUTHORIZATION));
        authCorsConfiguration.setAllowCredentials(true);
        return authCorsConfiguration;
    }
}
