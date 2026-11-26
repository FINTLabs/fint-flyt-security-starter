package no.novari.flyt.security

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SourceApplicationTest {
    @Test
    fun `ids and property prefixes are unique`() {
        assertThat(SourceApplication.entries.map { it.id }).doesNotHaveDuplicates()
        assertThat(SourceApplication.entries.map { it.propertyPrefix }).doesNotHaveDuplicates()
    }

    @Test
    fun `ids match the stored values`() {
        assertThat(SourceApplication.entries.associate { it.name to it.id }).containsExactly(
            entry("ACOS", 1),
            entry("EGRUNNERVERV", 2),
            entry("DIGISAK", 3),
            entry("VIGO", 4),
            entry("ALTINN", 5),
            entry("HMSREG", 6),
            entry("ISY_GRAVING", 7),
            entry("FSKYSS", 8),
            entry("SIDE", 9),
            entry("EAPPLY", 10),
            entry("CONEXUS", 11),
        )
    }

    @Test
    fun `fromId finds the source application`() {
        assertThat(SourceApplication.fromId(2)).isEqualTo(SourceApplication.EGRUNNERVERV)
        assertThat(SourceApplication.fromId(99)).isNull()
    }

    private fun entry(
        name: String,
        id: Long,
    ) = org.assertj.core.api.Assertions
        .entry(name, id)
}
