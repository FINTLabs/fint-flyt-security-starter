package no.novari.flyt.security

import org.springframework.security.core.Authentication

public object SourceApplicationAuthority {
    public const val PREFIX: String = "SOURCE_APPLICATION_ID_"

    public fun of(sourceApplicationId: Long): String = "$PREFIX$sourceApplicationId"
}

/** The source application of a caller on the gateway's external routes. */
public fun Authentication.sourceApplicationId(): Long =
    authorities
        .mapNotNull { it.authority }
        .filter { it.startsWith(SourceApplicationAuthority.PREFIX) }
        .singleOrNull()
        ?.removePrefix(SourceApplicationAuthority.PREFIX)
        ?.toLong()
        ?: error("Expected exactly one source application authority")
