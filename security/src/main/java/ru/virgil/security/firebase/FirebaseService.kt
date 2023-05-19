package ru.virgil.security.firebase

import com.google.auth.oauth2.GoogleCredentials
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseAuthException
import com.google.firebase.auth.FirebaseToken
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.stereotype.Service
import org.springframework.util.ResourceUtils
import java.io.FileInputStream
import java.io.IOException
import java.nio.file.Files
import javax.annotation.PostConstruct

@EnableConfigurationProperties(FirebaseSecurityProperties::class)
@Service
class FirebaseService(
    private val firebaseSecurityProperties: FirebaseSecurityProperties,
) {

    lateinit var webCredentialsJson: String

    @PostConstruct
    @Throws(IOException::class)
    private fun initFirebaseFromConfig() {
        try {
            FirebaseApp.getInstance()
        } catch (e: IllegalStateException) {
            val adminCredentialsFilePath = "classpath:%s".format(
                firebaseSecurityProperties.adminCredentialsFilePath
            )
            val credentialsFile = ResourceUtils.getFile(adminCredentialsFilePath)
            val options = FirebaseOptions.builder()
                .setCredentials(GoogleCredentials.fromStream(FileInputStream(credentialsFile)))
                .build()
            FirebaseApp.initializeApp(options)
        }
    }

    @PostConstruct
    @Throws(IOException::class)
    private fun initWebCredentialsFromFile() {
        val webCredentialsFilePath = "classpath:%s".format(firebaseSecurityProperties.webCredentialsFilePath)
        val credentialsFile = ResourceUtils.getFile(webCredentialsFilePath)
        webCredentialsJson = Files.readString(credentialsFile.toPath())
    }

    @Throws(FirebaseAuthException::class, IllegalArgumentException::class)
    fun decodeToken(rawFirebaseToken: String): FirebaseToken =
        FirebaseAuth.getInstance().verifyIdToken(rawFirebaseToken)
}
