package ru.virgil.example.util.security.policeman

import org.springframework.security.test.context.support.TestExecutionEvent
import org.springframework.security.test.context.support.WithSecurityContext
import ru.virgil.example.security.UserAuthority

@Retention(AnnotationRetention.RUNTIME)
@WithSecurityContext(factory = MockPoliceSecurityContextFactory::class, setupBefore = TestExecutionEvent.TEST_METHOD)
annotation class WithMockFirebasePoliceman(
    val authorities: Array<UserAuthority> = [UserAuthority.ROLE_POLICE],
    val firebaseUserId: String = "police-id",
    val firebaseAuthToken: String = "police-auth-token",
)
