package ru.virgil.example.image

import org.springframework.core.io.ResourceLoader
import org.springframework.stereotype.Service
import ru.virgil.example.user.UserDetails
import ru.virgil.utils.image.FileTypeService
import ru.virgil.utils.image.ImageService
import java.nio.file.Path
import java.util.*

@Service
class ImageService(
    resourceLoader: ResourceLoader,
    privateImageRepository: PrivateImageRepository,
    fileTypeService: FileTypeService,
) : ImageService<UserDetails, PrivateImageFile>(resourceLoader, privateImageRepository, fileTypeService) {

    override fun createPrivateImageFile(uuid: UUID, owner: UserDetails, imageFilePath: Path): PrivateImageFile {
        val privateImageFile = PrivateImageFile(owner, imageFilePath)
        privateImageFile.uuid = uuid
        return privateImageFile
    }
}
