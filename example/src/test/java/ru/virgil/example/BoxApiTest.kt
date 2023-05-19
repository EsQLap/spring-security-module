package ru.virgil.example

import com.google.common.truth.Truth
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.ObjectProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.ComponentScan
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import ru.virgil.example.box.*
import ru.virgil.example.system.rest.RestValues.PAGE_PARAM
import ru.virgil.example.system.rest.RestValues.PAGE_SIZE_PARAM
import ru.virgil.example.util.security.policeman.WithMockFirebasePoliceman
import ru.virgil.example.util.security.user.WithMockFirebaseUser
import ru.virgil.test_utils.AssertUtils
import ru.virgil.test_utils.fluent_request.RequestUtil
import ru.virgil.utils.Faker
import java.util.*

@SpringBootTest
@AutoConfigureMockMvc
@WithMockFirebaseUser
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ComponentScan("ru.virgil.test_utils", "ru.virgil.utils")
class BoxApiTest @Autowired constructor(
    private val assertUtils: AssertUtils,
    private val requestUtil: RequestUtil,
    private val faker: Faker,
    @Qualifier(BoxMocker.random)
    private val boxProvider: ObjectProvider<Box>,
) {

    @Test
    fun getAll() {
        val boxDtoList = requestUtil.get("/box?$PAGE_PARAM=$BOX_PAGE&$PAGE_SIZE_PARAM=$BOX_PAGE_SIZE")
            .receive(MutableList::class.java, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as List<BoxDto?>
        Truth.assertThat(boxDtoList).isNotEmpty()
        Truth.assertThat(boxDtoList.stream().findAny().orElseThrow()).isInstanceOf(BoxDto::class.java)
    }

    @Test
    fun get() {
        val box = boxProvider.getObject()
        val boxDto = requestUtil.get("/box/${box.uuid}")
            .receive(BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        Truth.assertThat(boxDto.weight).isAtLeast(10)
    }

    @Test
    fun createWithoutType() {
        val testDto = BoxDto(null, null, null, null, faker.appliance().brand(), 50000, 658f)
        requestUtil.post("/box")
            .exchange(testDto, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isBadRequest)
    }

    @Test
    fun create() {
        val testDto = BoxDto(type = BoxType.USUAL, description = "CREATED", price = 50000, weight = 658f)
        val createdDto = requestUtil.post("/box")
            .exchange(testDto, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        assertUtils.partialEquals(createdDto, testDto)
        val serverDto = requestUtil.get("/box/${createdDto.uuid}")
            .receive(BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        Truth.assertThat(serverDto).isEqualTo(createdDto)
    }

    @Test
    fun edit() {
        val testDto = BoxDto(type = BoxType.USUAL, description = "EDITED", price = 78434, weight = 456f)
        val box = boxProvider.getObject()
        val changedDto = requestUtil.put("/box/${box.uuid}")
            .exchange(testDto, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        assertUtils.partialEquals(changedDto, testDto)
        val serverDto = requestUtil.get("/box/${changedDto.uuid}")
            .receive(BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        Truth.assertThat(serverDto).isEqualTo(changedDto)
    }

    @Test
    fun delete() {
        val box = boxProvider.getObject()
        requestUtil.delete("/box/${box.uuid}")
            .and()
            .expect(MockMvcResultMatchers.status().isOk)
        requestUtil.get("/box/${box.uuid}")
            .and()
            .expect(MockMvcResultMatchers.status().isNotFound)
    }

    @Test
    fun createWeaponByUsualUser() {
        val testDto = BoxDto(type = BoxType.WEAPON, description = "CREATED-BY-USUAL-USER", price = 50000, weight = 658f)
        requestUtil.post("/box")
            .send(testDto)
            .and()
            .expect(MockMvcResultMatchers.status().isForbidden)
    }

    @Test
    @WithMockFirebasePoliceman
    fun createWeaponByPoliceman() {
        val testDto = BoxDto(type = BoxType.WEAPON, description = "CREATED-BY-POLICEMAN", price = 50000, weight = 658f)
        val createdDto = requestUtil.post("/box")
            .exchange(testDto, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        assertUtils.partialEquals(createdDto, testDto)
        val serverDto = requestUtil.get("/box/${createdDto.uuid}")
            .receive(BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        Truth.assertThat(createdDto).isEqualTo(serverDto)
    }

    @Test
    fun getAllWeaponsByUsualUser(): Unit {
        requestUtil.get("/box/weapons?$PAGE_PARAM=$BOX_PAGE&$PAGE_SIZE_PARAM=$BOX_PAGE_SIZE")
            .and()
            .expect(MockMvcResultMatchers.status().isForbidden)
    }

    @WithMockFirebasePoliceman
    @Test
    fun getAllWeaponsByPoliceman(): Unit {
        val testDto = BoxDto(type = BoxType.WEAPON, description = "CREATED-BY-POLICEMAN", price = 50000, weight = 658f)
        val serverDto = requestUtil.post("/box")
            .exchange(testDto, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as BoxDto
        assertUtils.partialEquals(serverDto, testDto)
        val weaponDtoList = requestUtil.get("/box/weapons?$PAGE_PARAM=$BOX_PAGE&$PAGE_SIZE_PARAM=$BOX_PAGE_SIZE")
            .receive(MutableList::class.java, BoxDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as List<BoxDto?>
        Truth.assertThat(weaponDtoList).contains(serverDto)
    }

    companion object {

        const val BOX_PAGE = 0
        const val BOX_PAGE_SIZE = 10
    }
}
