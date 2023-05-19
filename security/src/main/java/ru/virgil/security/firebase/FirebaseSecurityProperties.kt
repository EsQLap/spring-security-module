package ru.virgil.security.firebase

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "security.firebase")
data class FirebaseSecurityProperties(
    var adminCredentialsFilePath: String?,
    var webCredentialsFilePath: String?,
    var authPageTemplateName: String?,
)
