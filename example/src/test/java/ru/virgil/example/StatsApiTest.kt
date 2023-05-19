package ru.virgil.example

import com.google.common.truth.Truth
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.ComponentScan
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import ru.virgil.example.stats.StatsDto
import ru.virgil.example.util.security.user.WithMockFirebaseUser
import ru.virgil.test_utils.fluent_request.RequestUtil

@SpringBootTest
@AutoConfigureMockMvc
@WithMockFirebaseUser
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ComponentScan("ru.virgil.test_utils")
class StatsApiTest @Autowired constructor(private val requestUtil: RequestUtil) {

    @Throws(Exception::class)
    @Test
    fun getAll(): Unit {
        val statsDto = requestUtil.get("/stats/all")
            .receive(StatsDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as StatsDto
        Truth.assertThat(statsDto).isNotNull()
    }

    @Throws(Exception::class)
    @Test
    fun getMy(): Unit {
        val statsDto = requestUtil.get("/stats/my")
            .receive(StatsDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as StatsDto
        Truth.assertThat(statsDto).isNotNull()
    }
}
