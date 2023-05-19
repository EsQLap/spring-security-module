package ru.virgil.utils.image

import org.springframework.data.repository.CrudRepository
import org.springframework.data.repository.NoRepositoryBean
import ru.virgil.utils.base.entity.Identified
import java.util.*

@NoRepositoryBean
interface PrivateImageRepository<Owner : Identified, PrivateImage : ru.virgil.utils.image.PrivateImage<Owner>> :
    CrudRepository<PrivateImage, UUID> {

    fun findByOwnerAndUuid(owner: Owner, imageUuid: UUID): Optional<PrivateImage>
}
