package ru.firewall.policy

enum class NetworkType {
    WIFI,
    MOBILE,
}

enum class AccessRule {
    UNDECIDED,
    ALLOWED,
    DENIED,
}

enum class AccessDecision {
    BLOCK_AND_NOTIFY,
    ALLOW,
    BLOCK,
    BYPASS,
}

data class NetworkRules(
    val wifi: AccessRule = AccessRule.UNDECIDED,
    val mobile: AccessRule = AccessRule.UNDECIDED,
    val excluded: Boolean = false,
) {
    fun decide(network: NetworkType?): AccessDecision {
        if (excluded) return AccessDecision.BYPASS

        val rule = when (network) {
            NetworkType.WIFI -> wifi
            NetworkType.MOBILE -> mobile
            null -> return AccessDecision.BLOCK
        }
        return when (rule) {
            AccessRule.UNDECIDED -> AccessDecision.BLOCK_AND_NOTIFY
            AccessRule.ALLOWED -> AccessDecision.ALLOW
            AccessRule.DENIED -> AccessDecision.BLOCK
        }
    }

    fun withRule(network: NetworkType, rule: AccessRule): NetworkRules =
        when (network) {
            NetworkType.WIFI -> copy(wifi = rule)
            NetworkType.MOBILE -> copy(mobile = rule)
        }
}
