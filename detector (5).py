"""
Naija Scam Checker - v1 Rule-Based Detection Engine
-----------------------------------------------------
"""

import re

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
            "mara lafiya", "asibiti", "bimo", "giving birth", "accident",
            "medical attention", "injured", "needs medical",
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

    # NEW CATEGORY - covers the message your friends tested
    "third_party_relative_proxy": {
        "weight": 5,
        "phrases": [
            "messaging on behalf of", "message on behalf of", "i am your",
            "on behalf of your", "this is on behalf", "am contacting you on behalf",
            "reaching out on behalf",
        ],
    },

    "large_specific_transfer_to_account": {
        "weight": 5,
        "patterns": [
            # a naira-style number followed reasonably closely by "account" or a bank-account-length digit string
            r"send\s+\d{4,}\s+to\s+this\s+account",
            r"\bto\s+this\s+account\b",
            r"\b\d{10}\b",  # Nigerian bank account numbers are 10 digits
        ],
    },

    "virtual_kidnapping_extortion": {
        "weight": 12,
        "phrases": [
            "we have", "do not hang up", "do not contact police", "if you want to see",
            "gun to her head", "gun to his head", "we hold your", "no call any person",
            "come back alive",
        ],
    },

    "investment_ponzi_bait": {
        "weight": 5,
        "phrases": [
            "liquidity pool", "yield multiplier", "guaranteed returns", "double your",
            "no risk at all", "daily commission", "diamond project",
            "invest today", "compound daily",
        ],
    },

    "bureaucratic_euphemism": {
        "weight": 5,
        "phrases": [
            "compliance sweep", "demographic registry", "processing hold",
            "primary transaction instrument", "electronic validation",
            "device registry profiles", "chargeback dispute", "settlement payout",
            "terminal suspension",
        ],
    },

    "low_urgency_admin_excuse": {
        "weight": 4,
        "phrases": [
            "minor infraction", "safety wardens", "holding my handset",
            "using an associate's phone", "using a friend's phone", "recovery fee",
            "clear the recovery", "car papers",
        ],
    },

    "job_scam_upfront_fee": {
        "weight": 5,
        "phrases": [
            "shortlisted for an interview", "come with hardcopy", "verification form",
            "for verification", "screening fee", "you don scale the job",
        ],
    },

    "fake_grant_portal": {
        "weight": 4,
        "phrases": [
            "grant awards", "participants would be selected", "apply via the portal",
            "in training", "startup grant",
        ],
    },

    "mobile_money_account_request": {
        "weight": 4,
        "phrases": [
            "opay account", "palmpay account", "kuda account", "moniepoint account",
        ],
    },

    "subtle_grooming_micro_ask": {
        "weight": 3,
        "phrases": [
            "credit voucher", "data subscription", "banking app is locked",
            "app is locked until", "renew my data",
        ],
    },
}


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


READABLE_EXPLANATIONS = {
    "urgency_network_excuse": "Uses an urgency + 'can't call me' excuse to block verification",
    "kinship_trust_request": "Uses family/relationship language to build false trust",
    "recharge_card_bait": "Involves recharge card / airtime PIN transfer trick",
    "stranded_travel_bait": "Claims to be stranded, stopped by security/police, needing urgent money",
    "money_request_small_specific": "Requests a specific amount of money",
    "health_emergency_bait": "Uses a health/hospital emergency as bait",
    "fake_bank_alert": "Mimics a bank/BVN/OTP alert format",
    "suspicious_url": "Contains a suspicious or spoofed-looking link",
    "religious_closing": "Uses religious language to build trust/guilt",
    "delivery_logistics_hook": "Uses a delivery/logistics fee request",
    "too_good_to_be_true": "Offers unrealistic money/prizes for little effort",
    "romance_escalation": "Shows romance-scam escalation pattern",
    "third_party_relative_proxy": "A stranger claims to be messaging on behalf of your relative",
    "large_specific_transfer_to_account": "Asks for a large transfer to a specific account number",
    "virtual_kidnapping_extortion": "Extreme pressure tactic mimicking a kidnapping/extortion threat",
    "investment_ponzi_bait": "Promises guaranteed or unusually high investment returns",
    "bureaucratic_euphemism": "Uses vague official-sounding language to mask a scam request",
    "low_urgency_admin_excuse": "Uses a plausible, low-drama excuse to avoid a phone call",
    "job_scam_upfront_fee": "Job offer requesting an upfront fee before hiring",
    "fake_grant_portal": "Claims you're selected for a grant/funding programme",
    "mobile_money_account_request": "Directs payment to a mobile money account (OPay/PalmPay/Kuda/Moniepoint)",
    "subtle_grooming_micro_ask": "Small, low-pressure money request following emotional buildup",
}

CHIP_LABELS = {
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
    "third_party_relative_proxy": "Fake relative proxy",
    "large_specific_transfer_to_account": "Large transfer request",
    "virtual_kidnapping_extortion": "Extortion threat",
    "investment_ponzi_bait": "Investment/Ponzi bait",
    "bureaucratic_euphemism": "Official-sounding jargon",
    "low_urgency_admin_excuse": "Low-drama excuse",
    "job_scam_upfront_fee": "Upfront job fee",
    "fake_grant_portal": "Fake grant/funding",
    "mobile_money_account_request": "Mobile money request",
    "subtle_grooming_micro_ask": "Subtle micro-request",
}


def explain(result: dict) -> str:
    if not result["categories_matched"]:
        return "No known scam patterns detected in this message."
    lines = [f"- {READABLE_EXPLANATIONS.get(cat, cat)}" for cat in result["categories_matched"]]
    return "\n".join(lines)


def get_reason_chips(result: dict) -> list:
    if not result["categories_matched"]:
        return []
    return [CHIP_LABELS.get(cat, cat) for cat in result["categories_matched"]]


def what_to_do(result: dict) -> str:
    verdict = result["verdict"]
    if "HIGH RISK" in verdict:
        return "Don't respond, click any link, or call the number in this message. If this involves a threat to someone's safety, contact the police directly. Otherwise verify through the official app or a number you already trust."
    elif "SUSPICIOUS" in verdict:
        return "Pause before acting. Confirm this with the person or organisation directly, using a channel you already trust."
    elif "LOW RISK" in verdict:
        return "No major red flags, but stay alert if it asks for money, codes, or personal details."
    else:
        return "No known scam patterns detected. Still verify anything involving money or personal details."


if __name__ == "__main__":
    msg = "I am your messaging on behalf of your uncle he got into an accident he needs medical attention can you send 300000 to this account 0112511522"
    r = check_message(msg)
    print("Score:", r["score"])
    print("Verdict:", r["verdict"])
    print("Matched:", r["categories_matched"])
