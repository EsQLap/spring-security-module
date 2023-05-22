package ru.virgil.security

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.CorsConfigurationSource
import org.springframework.web.cors.UrlBasedCorsConfigurationSource
import ru.virgil.security.entity.AuthMethods
import ru.virgil.security.firebase.FirebaseAuthenticationFilter
import ru.virgil.security.firebase.FirebaseAuthorizationProvider
import java.util.*
import java.util.Map
import kotlin.collections.List
import kotlin.collections.listOf
import kotlin.collections.toTypedArray


@Configuration
class SecurityConfig(
    private val firebaseAuthorizationProvider: FirebaseAuthorizationProvider,
    private val authenticationEntryPoint: AuthenticationEntryPoint,
    private val securityProperties: SecurityProperties,
    private val objectMapper: ObjectMapper,
) : WebSecurityConfigurerAdapter() {

    @Throws(Exception::class)
    override fun configure(httpSecurity: HttpSecurity) {
        val propertyIgnoredPaths: List<String> = securityProperties.anonymousPaths
        httpSecurity // todo: стандартный редирект на страницу успешной безопасности
            // todo: разобраться, как включить
            .cors()
            .and()
            .csrf().disable()
            .authorizeRequests()
            .mvcMatchers(*AUTH_PAGE_PATHS.values.toTypedArray()).permitAll()
            .mvcMatchers("/", "/favicon.ico", "/error").permitAll()
            .mvcMatchers(*propertyIgnoredPaths.toTypedArray()).permitAll()
            .mvcMatchers("/**").authenticated()
            .and()
            .addFilterBefore(
                FirebaseAuthenticationFilter(authenticationManager(), securityProperties, objectMapper),
                UsernamePasswordAuthenticationFilter::class.java
            )
            .authenticationProvider(firebaseAuthorizationProvider) // todo: разобраться, как лучше реагировать на ошибки и не подставлять безопасность
        // .exceptionHandling()
        // .authenticationEntryPoint(authenticationEntryPoint)
    }

    @Bean
    protected fun corsConfigurationSource(): CorsConfigurationSource? {
        val authCorsConfiguration = buildAuthCorsConfiguration()
        val resultCorsConfiguration = buildResultCorsConfiguration()
        val configurationSource = UrlBasedCorsConfigurationSource()
        configurationSource.registerCorsConfiguration(AUTH_API_PATHS[AuthMethods.FIREBASE]!!, authCorsConfiguration)
        configurationSource.registerCorsConfiguration("/**", resultCorsConfiguration)
        return configurationSource
    }

    private fun buildResultCorsConfiguration(): CorsConfiguration {
        val resultCorsConfiguration = CorsConfiguration()
        resultCorsConfiguration.allowedOrigins = listOf(ORIGIN)
        resultCorsConfiguration.allowedHeaders = listOf(X_AUTH_TOKEN_HEADER, HttpHeaders.CONTENT_TYPE)
        resultCorsConfiguration.allowedMethods = HttpMethod.values().map { obj: HttpMethod -> obj.name }
        return resultCorsConfiguration
    }

    private fun buildAuthCorsConfiguration(): CorsConfiguration {
        val authCorsConfiguration = CorsConfiguration()
        authCorsConfiguration.allowedOrigins = listOf(ORIGIN)
        authCorsConfiguration.allowedMethods = listOf(HttpMethod.POST.name)
        authCorsConfiguration.allowedHeaders = listOf(HttpHeaders.AUTHORIZATION)
        authCorsConfiguration.exposedHeaders = listOf(X_AUTH_TOKEN_HEADER)
        return authCorsConfiguration
    }

    companion object {

        const val ORIGIN = "http://localhost:4200"
        const val X_AUTH_TOKEN_HEADER = "X-Auth-Token"

        @JvmField
        val AUTH_API_PATHS = Map.of(
            AuthMethods.FIREBASE, "/auth/firebase"
        )

        @JvmField
        val AUTH_PAGE_PATHS = Map.of(
            AuthMethods.FIREBASE, "/auth/firebase/page/**"
        )
    }
}
