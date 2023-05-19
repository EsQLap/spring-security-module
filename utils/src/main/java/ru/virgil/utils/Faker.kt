package ru.virgil.utils

import net.datafaker.Avatar
import net.datafaker.Faker
import org.springframework.stereotype.Component
import java.net.URI

@Component
open class Faker : Faker() {

    val customUrl = URI("https://picsum.photos/")

    /**
     * Переопределение стандартного метода
     */
    override fun avatar(): Avatar = getProvider(CustomAvatar::class.java) { CustomAvatar(this) }

    /**
     * Дополнительный метод с настройками картинок
     */
    fun image(): CustomImage = getProvider(CustomImage::class.java) { CustomImage() }

    inner class CustomImage {

        val defaultSize = 256

        fun url(): String = customUrl.resolve("$defaultSize").toString()

        fun url(size: Int): String = customUrl.resolve("$size").toString()

        fun url(height: Int, width: Int): String = customUrl.resolve("$height").resolve("$width").toString()
    }

    inner class CustomAvatar(faker: Faker) : Avatar(faker) {

        val defaultSize = 200

        override fun image(): String = customUrl.resolve("$defaultSize").toString()
    }
}
