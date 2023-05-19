package ru.virgil.example.user

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/user_details")
class UserDetailsController(
    private val userDetailsService: UserDetailsService,
) : UserDetailsMapper {

    @GetMapping
    fun get(): UserDetailsDto {
        val currentUser = userDetailsService.getCurrentUser()
        return currentUser.toDto()
    }
}
