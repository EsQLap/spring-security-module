package ru.virgil.example.image

import kotlin.io.path.name

interface ImageMapper {

    fun PrivateImageFile.toDto(): PrivateImageFileDto {
        return PrivateImageFileDto(uuid, createdAt, updatedAt, this.fileLocation.name)
    }
}
