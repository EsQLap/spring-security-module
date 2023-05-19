package ru.virgil.example.image

import ru.virgil.example.system.entity.OwnedEntity
import ru.virgil.example.user.UserDetails
import ru.virgil.utils.image.PrivateImage
import java.nio.file.Path
import javax.persistence.Entity
import javax.persistence.Transient

@Entity
class PrivateImageFile(
    owner: UserDetails,
    fileLocation: Path,
) : OwnedEntity(owner), PrivateImage<UserDetails> {

    @get:Transient
    override var fileLocation: Path
        get() = Path.of(location)
        set(value) {
            location = value.toString()
        }

    private var location: String = fileLocation.toString()
}
