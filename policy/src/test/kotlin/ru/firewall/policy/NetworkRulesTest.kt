package ru.firewall.policy

import org.junit.Assert.assertEquals
import org.junit.Test

class NetworkRulesTest {
    @Test
    fun allCombinationsUseOnlyTheCurrentNetworkRule() {
        val expected = mapOf(
            AccessRule.UNDECIDED to AccessDecision.BLOCK_AND_NOTIFY,
            AccessRule.ALLOWED to AccessDecision.ALLOW,
            AccessRule.DENIED to AccessDecision.BLOCK,
        )
        for ((wifi, wifiDecision) in expected) {
            for ((mobile, mobileDecision) in expected) {
                val rules = NetworkRules(wifi = wifi, mobile = mobile)
                assertEquals(wifiDecision, rules.decide(NetworkType.WIFI))
                assertEquals(mobileDecision, rules.decide(NetworkType.MOBILE))
                assertEquals(AccessDecision.BYPASS, rules.copy(excluded = true).decide(NetworkType.WIFI))
                assertEquals(AccessDecision.BYPASS, rules.copy(excluded = true).decide(NetworkType.MOBILE))
            }
        }
    }

    @Test
    fun newRulesAreUndecidedOnBothNetworks() {
        val rules = NetworkRules()
        assertEquals(AccessDecision.BLOCK_AND_NOTIFY, rules.decide(NetworkType.WIFI))
        assertEquals(AccessDecision.BLOCK_AND_NOTIFY, rules.decide(NetworkType.MOBILE))
    }

    @Test
    fun updatingOneNetworkPreservesTheOtherRuleAndTheExclusion() {
        val rules = NetworkRules(wifi = AccessRule.ALLOWED, excluded = true)
        val updated = rules.withRule(NetworkType.MOBILE, AccessRule.DENIED)
            .withRule(NetworkType.WIFI, AccessRule.UNDECIDED)
        assertEquals(NetworkRules(mobile = AccessRule.DENIED, excluded = true), updated)
    }

    @Test
    fun anUnknownNetworkDoesNotUseAnotherNetworksPermission() {
        val rules = NetworkRules(wifi = AccessRule.ALLOWED, mobile = AccessRule.ALLOWED)
        assertEquals(AccessDecision.BLOCK, rules.decide(null))
        assertEquals(AccessDecision.BYPASS, rules.copy(excluded = true).decide(null))
    }
}
