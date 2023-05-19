package ru.virgil.security.firebase

import com.fasterxml.jackson.core.JsonProcessingException
import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.*
import org.springframework.web.servlet.ModelAndView
import ru.virgil.security.SecurityConfig
import ru.virgil.security.entity.AuthMethods
import ru.virgil.security.entity.AuthRecord
import ru.virgil.security.header.AuthorizationHeader
import ru.virgil.security.header.WwwAuthenticateHeader
import ru.virgil.security.service.FirebaseAuthRecordsService
import java.io.IOException
import java.util.*
import java.util.Map
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@RestController
@RequestMapping("/auth/firebase")
class FirebaseAuthController(
    private val firebaseAuthRecordsService: FirebaseAuthRecordsService,
    private val firebaseService: FirebaseService,
    private val objectMapper: ObjectMapper,
) {

    @ResponseStatus(HttpStatus.BAD_REQUEST)
    @ExceptionHandler(ClassCastException::class, IllegalArgumentException::class)
    @Throws(IOException::class)
    fun handleBadRequestExceptions(response: HttpServletResponse, exception: Exception) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST, exception.localizedMessage)
    }

    @ResponseStatus(HttpStatus.NOT_FOUND)
    @ExceptionHandler(NullPointerException::class)
    @Throws(IOException::class)
    fun handleNotFoundExceptions(response: HttpServletResponse, exception: Exception) {
        response.sendError(HttpServletResponse.SC_NOT_FOUND, exception.localizedMessage)
    }

    @Deprecated("Нельзя передавать UUID в адресе")
    @GetMapping("/page")
    @Throws(JsonProcessingException::class)
    fun refactoredAuthPage(
        @RequestParam(required = false) authRecordUuid: UUID?,
        @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) authorizationHeader: String,
    ): ModelAndView {
        // todo: если нет хедера и параметра, то проводится веб-авторизация
        val recordUuid = authRecordUuid ?: firebaseAuthRecordsService.extractAuthRecordUuid(
            authorizationHeader
        )
        val putCallbackAuthorizationHeader = AuthorizationHeader(
            AuthMethods.FIREBASE,
            Map.of(FirebaseAuthRecordsService.AUTH_RECORD_UUID_CREDENTIAL, recordUuid.toString())
        )
        val authRecordUpdatePath = "/auth/firebase/page/record"
        val modelAndView = ModelAndView()
        modelAndView.modelMap.addAttribute(
            "auth_record_callback_header",
            objectMapper.writeValueAsString(putCallbackAuthorizationHeader)
        )
        modelAndView.modelMap.addAttribute(
            "firebase_credentials_json",
            firebaseService.webCredentialsJson
        )
        modelAndView.modelMap.addAttribute("auth_record_callback_path", authRecordUpdatePath)
        modelAndView.viewName = "firebase_auth_page"
        return modelAndView
    }

    @GetMapping("/page/record")
    fun getAuthRecord(@RequestHeader(HttpHeaders.AUTHORIZATION) authorizationHeader: String): AuthRecord {
        val authRecordUuid = firebaseAuthRecordsService.extractAuthRecordUuid(authorizationHeader)
        return firebaseAuthRecordsService.getAuthRecord(authRecordUuid)!!
    }

    @PostMapping("/page/record")
    @Throws(IOException::class)
    fun createAuthRecord(request: HttpServletRequest, response: HttpServletResponse) {
        val authRecord = firebaseAuthRecordsService.createAuthRecord()
        val exampleHeader = objectMapper.writeValueAsString(
            AuthorizationHeader(
                AuthMethods.FIREBASE,
                Map.of(FirebaseAuthRecordsService.AUTH_RECORD_UUID_CREDENTIAL, "value")
            )
        )
        val challenges = Map.of(
            FirebaseAuthRecordsService.AUTH_RECORD_UUID_CREDENTIAL, authRecord.toString(),
            "info", "Send %s Header to GET %s, pass authentication and then GET Firebase Token from /page/record"
                .format(HttpHeaders.AUTHORIZATION, SecurityConfig.AUTH_PAGE_PATHS[AuthMethods.FIREBASE]),
            "auth_header_example", exampleHeader
        )
        val wwwAuthenticateHeader = WwwAuthenticateHeader(AuthMethods.FIREBASE, challenges)
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, objectMapper.writeValueAsString(wwwAuthenticateHeader))
    }

    @PutMapping("/page/record")
    fun editAuthRecord(
        @RequestHeader(HttpHeaders.AUTHORIZATION) authorizationHeader: String,
        @RequestBody authRecord: AuthRecord,
    ) {
        val authRecordUuid = firebaseAuthRecordsService.extractAuthRecordUuid(authorizationHeader)
        firebaseAuthRecordsService.editAuthRecord(authRecordUuid, authRecord)
    }

    @DeleteMapping("/page/record")
    fun deleteAuthRecord(@RequestHeader(HttpHeaders.AUTHORIZATION) authorizationHeader: String) {
        val authRecordUuid = firebaseAuthRecordsService.extractAuthRecordUuid(authorizationHeader)
        firebaseAuthRecordsService.deleteAuthRecord(authRecordUuid)
    }
}
