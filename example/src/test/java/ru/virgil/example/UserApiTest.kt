package ru.virgil.example

import com.google.common.truth.Truth
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.ComponentScan
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import ru.virgil.example.user.UserDetailsDto
import ru.virgil.example.util.security.user.WithMockFirebaseUser
import ru.virgil.test_utils.fluent_request.RequestUtil

@SpringBootTest
@AutoConfigureMockMvc
@WithMockFirebaseUser
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ComponentScan("ru.virgil.test_utils")
class UserApiTest @Autowired constructor(private val requestUtil: RequestUtil) {

    @Test
    @Throws(Exception::class)
    fun get() {
        val userDetailsDto = requestUtil.get("/user_details")
            .receive(UserDetailsDto::class.java)
            .and()
            .expect(MockMvcResultMatchers.status().isOk) as UserDetailsDto
        Truth.assertThat(userDetailsDto).isNotNull()
    }
}
