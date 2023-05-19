package ru.virgil.example

import com.google.common.truth.Truth
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.ComponentScan
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import ru.virgil.example.image.ImageService
import ru.virgil.example.image.PrivateImageFile
import ru.virgil.example.image.PrivateImageFileDto
import ru.virgil.example.user.UserDetails
import ru.virgil.example.util.security.user.WithMockFirebaseUser
import ru.virgil.test_utils.fluent_request.RequestUtil
import ru.virgil.utils.image.FileTypeService
import ru.virgil.utils.image.ImageMockService
import java.util.*

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ComponentScan("ru.virgil.test_utils")
class FileImageApiTest @Autowired constructor(
    private val imageMockService: ImageMockService<UserDetails, PrivateImageFile>,
    private val imageService: ImageService,
    private val requestUtil: RequestUtil,
    private val fileTypeService: FileTypeService,
) {

    @Test
    @WithMockFirebaseUser
    @Throws(Exception::class)
    fun postPrivateImage() {
        val privateImageFileDto = requestUtil.postMultipart("/image/private")
            .file(imageMockService.mockAsMultipart())
            .receive(PrivateImageFileDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as PrivateImageFileDto
        Truth.assertThat(privateImageFileDto).isNotNull()
    }

    @Throws(Exception::class)
    @WithMockFirebaseUser
    @Test
    fun getPrivateImage(): Unit {
        val privateImageFileDto = requestUtil.postMultipart("/image/private")
            .file(imageMockService.mockAsMultipart())
            .receive(PrivateImageFileDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as PrivateImageFileDto
        Truth.assertThat(privateImageFileDto).isNotNull()
        val byteArray = requestUtil["/image/private/%s".formatted(privateImageFileDto.uuid)]
            .receiveAsBytes()
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as ByteArray
        Truth.assertThat(fileTypeService.getImageMimeType(byteArray)).contains("image/")
    }

    @Throws(Exception::class)
    @WithMockFirebaseUser
    @Test
    fun getProtectedImage(): Unit {
        val byteArray = requestUtil.get("/image/protected/image.jpg")
            .receiveAsBytes()
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as ByteArray
        Truth.assertThat(fileTypeService.getImageMimeType(byteArray)).contains("image/")
    }

    @Throws(Exception::class)
    @Test
    fun getPublicImage(): Unit {
        val byteArray = requestUtil.get("/image/public/image.jpg")
            .receiveAsBytes()
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as ByteArray
        Truth.assertThat(fileTypeService.getImageMimeType(byteArray)).contains("image/")
    }

    @Throws(Exception::class)
    @WithMockFirebaseUser
    @Test
    fun getNotExisting(): Unit {
        requestUtil.get("/image/public/not_existing.jpg")
            .and()
            .expect(MockMvcResultMatchers.status().isNotFound)
        requestUtil.get("/image/protected/not_existing.jpg")
            .and()
            .expect(MockMvcResultMatchers.status().isNotFound)
        requestUtil.get("/image/protected/%s".format(UUID.randomUUID()))
            .and()
            .expect(MockMvcResultMatchers.status().isNotFound)
    }

    /**
     * Сделал удаление после разрушения компонента [ImageMockService], может удалить нужные пользвоателю картинки,
     * костыль.
     */
    @AfterAll
    fun cleanUp() {
        // TODO при запуске _всех_ тестов не срабатывает, при запуска _одного_ – срабатывает
    }
}
