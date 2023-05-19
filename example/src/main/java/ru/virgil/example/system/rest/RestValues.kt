package ru.virgil.example.system.rest

/**
 * Можно выделять постоянно повторяемые в API параметры в отдельный объект.
 * Это защитит от расхождения в названиях, типа pages и page.
 * И позволит не повторять названия параметров в каждом контроллере.
 */
object RestValues {

    const val PAGE_PARAM = "page"
    const val PAGE_SIZE_PARAM = "size"
}
