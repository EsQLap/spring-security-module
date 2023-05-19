package ru.virgil.example.image

import org.springframework.stereotype.Service
import ru.virgil.example.user.UserDetails
import ru.virgil.utils.Faker
import ru.virgil.utils.image.ImageMockService
import ru.virgil.utils.image.ImageProperties
import ru.virgil.utils.image.ImageService

@Service
class ImageMockService(
    imageService: ImageService<UserDetails, PrivateImageFile>,
    faker: Faker,
    imageProperties: ImageProperties,
) : ImageMockService<UserDetails, PrivateImageFile>(imageService, faker, imageProperties)
