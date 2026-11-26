package no.novari.flyt.security

/**
 * The FLYT source applications. [id] is the stored and transmitted form (database, Kafka, REST) and never changes.
 * [clientIdProperty] holds the source application's NAM client ID, from the secret authorization-service owns.
 */
public enum class SourceApplication(
    public val id: Long,
    public val displayName: String,
    key: String,
) {
    ACOS(1, "Acos Interact", "acos"),
    EGRUNNERVERV(2, "eGrunnerverv", "egrunnerverv"),
    DIGISAK(3, "Digisak", "digisak"),
    VIGO(4, "VIGO", "vigo"),
    ALTINN(5, "Altinn", "altinn"),
    HMSREG(6, "HMSReg", "hmsreg"),
    ISY_GRAVING(7, "ISY Graving", "isygraving"),
    FSKYSS(8, "FSkyss", "fskyss"),
    SIDE(9, "SiDE", "side"),
    EAPPLY(10, "eApply", "eapply"),
    CONEXUS(11, "Conexus", "conexus"),
    ;

    /** Prefix of the source application's properties, e.g. `fint.flyt.acos`. */
    public val propertyPrefix: String = "fint.flyt.$key"

    public val clientIdProperty: String = "$propertyPrefix.sso.client-id"

    public companion object {
        public fun fromId(id: Long): SourceApplication? = entries.firstOrNull { it.id == id }
    }
}
