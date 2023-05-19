package ru.virgil.security

import org.springframework.boot.context.properties.ConfigurationProperties


@ConfigurationProperties(prefix = "security")
data class SecurityProperties(
    /**
     * По этим путям можно будет заходить анонимно
     */
    var anonymousPaths: List<String> = ArrayList(),
    /**
     * Использовать для сессий заголовок X-Auth-Token вместо Cookies
     */
    var useXAuthToken: Boolean = false,
    /**
     * Отключить редиректы после успешной авторизации
     */
    var disablePostAuthRedirect: Boolean = false,
)
