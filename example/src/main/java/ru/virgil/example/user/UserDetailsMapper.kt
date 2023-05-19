package ru.virgil.example.user

interface UserDetailsMapper {

    fun UserDetails.toDto(): UserDetailsDto = UserDetailsDto(createdAt, updatedAt, uuid, name)
}
