package ru.virgil.example.box

import org.springframework.security.access.prepost.PostAuthorize
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.web.bind.annotation.*
import ru.virgil.example.system.rest.RestValues
import ru.virgil.example.truck.TruckService
import java.util.*
import javax.annotation.security.RolesAllowed

@RestController
@RequestMapping("/box")
class BoxController(
    private val truckService: TruckService,
    private val boxService: BoxService,
    private val boxSecurity: BoxSecurity,
) : BoxMapper {

    @GetMapping
    fun getAll(
        @RequestParam(RestValues.PAGE_PARAM) page: Int, @RequestParam(RestValues.PAGE_SIZE_PARAM) size: Int,
    ): List<BoxDto> = boxService.getAll(page, size).stream()
        .map { it.toDto() }
        .toList()

    @RolesAllowed("ROLE_POLICE")
    @GetMapping("/weapons")
    fun getAllWeapons(): List<BoxDto> = boxService.getAllMyWeapons().stream()
        .map { it.toDto() }
        .toList()

    @GetMapping("/{uuid}")
    @PostAuthorize(
        """
        hasRole('ROLE_POLICE') and @boxSecurity.hasWeapon(returnObject)
        or hasRole('ROLE_USER') and not @boxSecurity.hasWeapon(returnObject)
        """
    )
    operator fun get(@PathVariable uuid: UUID): BoxDto {
        val box = boxService.get(uuid)
        return box.toDto()
    }

    @PostMapping
    @PreAuthorize(
        """
        hasRole('ROLE_POLICE') and @boxSecurity.hasWeapon(#boxDto)
        or hasRole('ROLE_USER') and not @boxSecurity.hasWeapon(#boxDto)
        """
    )
    fun post(@RequestBody boxDto: BoxDto): BoxDto {
        // TODO: Заменить на Object Provider
        val assignedTruck = truckService.assignTruck()
        val createdBox = boxService.create(assignedTruck, boxDto)
        return createdBox.toDto()
    }

    @PutMapping("/{uuid}")
    fun put(@PathVariable uuid: UUID, @RequestBody boxDto: BoxDto): BoxDto {
        val serverBox = boxService.edit(uuid, boxDto)
        return serverBox.toDto()
    }

    @DeleteMapping("/{uuid}")
    fun delete(@PathVariable uuid: UUID) {
        boxService.delete(uuid)
    }
}
