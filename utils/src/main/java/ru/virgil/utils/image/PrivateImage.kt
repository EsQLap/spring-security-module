package ru.virgil.utils.image

import ru.virgil.utils.base.entity.Identified
import ru.virgil.utils.base.entity.Owned
import java.nio.file.Path

interface PrivateImage<Owner : Identified> : Owned<Owner>, Identified {

    var fileLocation: Path
}
