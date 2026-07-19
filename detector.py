"""
Naija Scam Checker - v1 Rule-Based Detection Engine
-----------------------------------------------------
Scores a message (Pidgin, Yoruba, Igbo, Hausa, or English) for scam likelihood
based on pattern categories found in real Nigerian WhatsApp/SMS scams.

This is v1: rule-based, transparent, and editable. Every rule is a phrase
or pattern pulled from real scam examples. As we collect more real messages,
we add more phrases to each category.

Usage:
    python3 detector.py
    (then paste a message when prompted, or import check_message() elsewhere)
"""

import re

# -----------------------------------------------------------------------
# RULE CATEGORIES
# Each category = (weight, list of phrases/patterns to search for)
# Weight = how strong a signal this category is on its own (1-5)
# -----------------------------------------------------------------------

RULES = {

    "urgency_network_excuse": {
        "weight": 4,
        "phrases": [
            "network bad", "network dey down", "network isn't", "phone isn't receiving",
            "ko gba ipe dada", "fon yi", "network problem", "can't call me",
            "abeg call me later", "network dey slow", "no gree call", "yara", "yara se",
        ],
    },

    "kinship_trust_request": {
        "weight": 3,
        "phrases": [
            "omo mi", "nna", "oga", "madam", "my child", "my son", "my daughter",
            "biko", "ejo", "abeg", "my brother", "my sister", "uncle", "auntie",
            "dan allah", "malam", "baba", "mama", "nwanne m",
        ],
    },

    "recharge_card_bait": {
        "weight": 4,
        "phrases": [
            "recharge card", "recharge pin", "eree-kadi", "airtime", "card pin",
            "read them back", "read the numbers",
        ],
    },

    "money_request_small_specific": {
        "weight": 4,
        # matches naira amounts like N2,000 / ₦2000 / 2k / 30k
        "patterns": [
            r"[nN₦]\s?\d{1,3}(,\d{3})*(\.\d+)?\b",
            r"\b\d+k\b",
        ],
    },

    "health_emergency_bait": {
        "weight": 4,
        "phrases": [
            "hospital", "sick", "surgery", "school fees", "aisan", "ile iwosan",
            "emergency", "doctor", "dokita", "ọrịa", "urgent help", "very urgent",
            "mara lafiya", "asibiti", "bimo", "giving birth",
        ],
    },

    "fake_bank_alert": {
        "weight": 7,
        "phrases": [
            "debit acct", "credit acct", "txn:", "bvn", "atm card", "deactivated",
            "reactivate your account", "blocked", "cbn policy", "unauthorized attempt",
            "otp", "customer care", "helpdesk", "an toshe", "asusun", "kyc",
            "verify-bvn", "sabunta bayanai",
        ],
    },

    "suspicious_url": {
        "weight": 5,
        "patterns": [
            r"https?://[^\s]+",
            r"www\.[^\s]+\.(online|xyz|top|info|site|click)",
            r"[a-z0-9-]+bank[a-z0-9-]*\.(com|online|net)",
        ],
    },

    "religious_closing": {
        "weight": 2,
        "phrases": [
            "god bless", "olorun a bukun", "god will protect", "god will bless",
            "in the name of god", "chukwu", "olorun", "allah ya albarkace",
            "dan allah",
        ],
    },

    "stranded_travel_bait": {
        "weight": 4,
        "phrases": [
            "security stopped me", "stranded", "checkpoint", "on my way to",
            "nchekwa jidere m", "njem", "police stopped", "hapụ m", "let me go",
            "let them release me",
        ],
    },

    "delivery_logistics_hook": {
        "weight": 3,
        "phrases": [
            "dispatch rider", "waybill", "delivery fee", "release it", "parcel",
            "clearance fee", "gig logistics", "collect your package",
        ],
    },

    "too_good_to_be_true": {
        "weight": 4,
        "phrases": [
            "congratulations", "you have been selected", "empowerment", "grant",
            "earn n", "daily just by", "part-time worker", "claim your funds",
            "free money", "double your money", "tallafi", "kyautar", "gwamnatin",
            "palliative",
        ],
    },

    "romance_escalation": {
        "weight": 3,
        "phrases": [
            "handsome", "beautiful", "nice name", "why your photo hidden",
            "send your pics", "sexy pics", "nude", "big boobs",
        ],
    },
}

# -----------------------------------------------------------------------
# SCORING
# -----------------------------------------------------------------------

def check_message(message: str) -> dict:
    text = message.lower()
    hits = []
    total_score = 0

    for category, rule in RULES.items():
        matched = False

        if "phrases" in rule:
            for phrase in rule["phrases"]:
                if phrase.lower() in text:
                    matched = True
                    break

        if not matched and "patterns" in rule:
            for pattern in rule["patterns"]:
                if re.search(pattern, text, re.IGNORECASE):
                    matched = True
                    break

        if matched:
            hits.append(category)
            total_score += rule["weight"]

    # Verdict thresholds - tune these as we test against more real messages
    if total_score >= 10:
        verdict = "HIGH RISK - likely scam"
    elif total_score >= 5:
        verdict = "SUSPICIOUS - be careful, verify independently"
    elif total_score > 0:
        verdict = "LOW RISK - minor flags, still stay alert"
    else:
        verdict = "NO OBVIOUS RED FLAGS - but scams evolve, stay sharp"

    return {
        "score": total_score,
        "verdict": verdict,
        "categories_matched": hits,
    }


def get_reason_chips(result: dict) -> list:
    """Returns short 2-3 word labels for each matched category, for chip display."""
    if not result["categories_matched"]:
        return []

    chip_labels = {
        "urgency_network_excuse": "Urgency pressure",
        "kinship_trust_request": "False trust language",
        "recharge_card_bait": "Recharge card trick",
        "stranded_travel_bait": "Stranded/travel bait",
        "money_request_small_specific": "Money request",
        "health_emergency_bait": "Health emergency bait",
        "fake_bank_alert": "Bank impersonation",
        "suspicious_url": "Suspicious link",
        "religious_closing": "Guilt/blessing closer",
        "delivery_logistics_hook": "Fake delivery fee",
        "too_good_to_be_true": "Too good to be true",
        "romance_escalation": "Romance escalation",
    }
    return [chip_labels.get(cat, cat) for cat in result["categories_matched"]]


def what_to_do(result: dict) -> str:
    """Returns a short recommended action based on the verdict level."""
    verdict = result["verdict"]
    if "HIGH RISK" in verdict:
        return "Don't respond, click any link, or call the number in this message. Verify through the official app or a number you already trust."
    elif "SUSPICIOUS" in verdict:
        return "Pause before acting. Confirm this with the person or organisation directly, using a channel you already trust."
    elif "LOW RISK" in verdict:
        return "No major red flags, but stay alert if it asks for money, codes, or personal details."
    else:
        return "No known scam patterns detected. Still verify anything involving money or personal details."


def explain(result: dict) -> str:
    if not result["categories_matched"]:
        return "No known scam patterns detected in this message."

    readable = {
        "urgency_network_excuse": "Uses an urgency + 'can't call me' excuse to block verification",
        "kinship_trust_request": "Uses family/relationship language to build false trust",
        "recharge_card_bait": "Involves recharge card / airtime PIN transfer trick",
        "stranded_travel_bait": "Claims to be stranded, stopped by security/police, needing urgent money",
        "money_request_small_specific": "Requests a specific amount of money",
        "health_emergency_bait": "Uses a health/hospital emergency as bait",
        "fake_bank_alert": "Mimics a bank/BVN/OTP alert format",
        "suspicious_url": "Contains a suspicious or spoofed-looking link",
        "religious_closing": "Uses religious language to build trust/guilt",
        "delivery_logistics_hook": "Uses a fake delivery/logistics fee request",
        "too_good_to_be_true": "Offers unrealistic money/prizes for little effort",
        "romance_escalation": "Shows romance-scam escalation pattern",
    }
    lines = [f"- {readable.get(cat, cat)}" for cat in result["categories_matched"]]
    return "\n".join(lines)


# -----------------------------------------------------------------------
# CLI TEST MODE
# -----------------------------------------------------------------------

if __name__ == "__main__":
    print("=== Naija Scam Checker v1 (rule-based) ===")
    print("Paste a message below and press Enter:\n")
    msg = input("> ")
    result = check_message(msg)
    print(f"\nScore: {result['score']}")
    print(f"Verdict: {result['verdict']}")
    print("\nWhy:")
    print(explain(result))
