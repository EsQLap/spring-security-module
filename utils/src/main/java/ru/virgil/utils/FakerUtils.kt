package ru.virgil.utils

import org.springframework.stereotype.Component

@Component
@Deprecated("Use Faker", ReplaceWith("Faker", "ru.virgil.utils"))
class FakerUtils : Faker()
