package ru.virgil.utils.base.entity

import java.time.LocalDateTime
import java.time.temporal.ChronoUnit

interface Timed {

    var createdAt: LocalDateTime
    var updatedAt: LocalDateTime

    object LocalDateTimeExtensions {

        private val THRESHOLD = ChronoUnit.MILLIS

        /**
         * Округляет дату до секунд. Позволяет избежать бага с округлением времени в базе данных.
         *
         * todo: С каждым выходом Spring надо проверять, не исправилось ли. Обещали исправить.
         * Для этого заменяем [ChronoUnit.MILLIS] на [ChronoUnit.NANOS].
         */
        fun LocalDateTime.databaseTruncate(): LocalDateTime = this.truncatedTo(THRESHOLD)
    }
}
