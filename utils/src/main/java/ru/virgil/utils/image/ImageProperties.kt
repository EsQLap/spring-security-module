package ru.virgil.utils.image

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "images")
data class ImageProperties(val cleanOnDestroy: Boolean = true)
