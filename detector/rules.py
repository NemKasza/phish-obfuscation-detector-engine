import re
from urllib.parse import urlparse


def detect_auth_header_failures(msg):
    """Detects SPF, DKIM, and DMARC authentication failures in email headers."""
    auth_status = {"spf": "NOT_FOUND", "dkim": "NOT_FOUND", "dmarc": "NOT_FOUND"}

    if not msg:
        return {
            "detected": False,
            "severity": "NONE",
            "reason": "No email metadata available",
            "indicators": [],
            "status": auth_status
        }

    indicators = []

    # Extract authentication headers
    auth_results = msg.get_all('Authentication-Results', [])
    received_spf = msg.get_all('Received-SPF', [])
    combined_auth = " ".join([str(h).lower() for h in auth_results + received_spf])

    # Evaluate SPF
    if "spf=fail" in combined_auth or "received-spf: fail" in combined_auth:
        auth_status["spf"] = "FAIL"
        indicators.append("spf_failure")
    elif "spf=softfail" in combined_auth:
        auth_status["spf"] = "SOFTFAIL"
        indicators.append("spf_softfail")
    elif "spf=pass" in combined_auth or "received-spf: pass" in combined_auth:
        auth_status["spf"] = "PASS"

    # Evaluate DKIM
    if "dkim=fail" in combined_auth:
        auth_status["dkim"] = "FAIL"
        indicators.append("dkim_failure")
    elif "dkim=pass" in combined_auth:
        auth_status["dkim"] = "PASS"

    # Evaluate DMARC
    if "dmarc=fail" in combined_auth or "action=reject" in combined_auth or "action=quarantine" in combined_auth:
        auth_status["dmarc"] = "FAIL"
        indicators.append("dmarc_failure")
    elif "dmarc=pass" in combined_auth:
        auth_status["dmarc"] = "PASS"

    if not indicators:
        return {
            "detected": False,
            "severity": "NONE",
            "reason": "Header authentication checks passed or no explicit failures recorded",
            "indicators": [],
            "status": auth_status
        }

    severity = "HIGH" if "dmarc_failure" in indicators or "spf_failure" in indicators else "MEDIUM"

    return {
        "detected": True,
        "severity": severity,
        "reason": f"Email authentication failures detected ({', '.join(indicators)})",
        "indicators": indicators,
        "status": auth_status
    }


def is_likely_gibberish(s):
    """
    Evaluates whether a long string is artificial evasion gibberish vs concatenated technical identifiers.
    """
    # 1. Filter out CamelCase / PascalCase concatenated identifiers (e.g., MicrosoftSecurityServices)
    if re.search(r'[a-z][A-Z]', s):
        sub_words = re.findall(r'[A-Z][a-z]+|[a-z]+', s)
        if len(sub_words) >= 2 and all(len(w) >= 2 for w in sub_words):
            return False  # Legitimate concatenated word structure

    lower_s = s.lower()

    # 2. Vowel Ratio Analysis (Natural text averages 25%-50% vowels)
    vowels = set("aeiou")
    vowel_count = sum(1 for char in lower_s if char in vowels)
    vowel_ratio = vowel_count / len(lower_s)

    # Extremely low (<18%) or high (>60%) vowel ratios indicate artificial gibberish
    if vowel_ratio < 0.18 or vowel_ratio > 0.60:
        return True

    # 3. Consecutive Consonants Check
    # Natural English rarely contains 5 or more consecutive consonants
    if re.search(r'[bcdfghjklmnpqrstvwxz]{5,}', lower_s):
        return True

    return False


def detect_gibberish_strings(text):
    """Detects high-entropy random strings used for Bayesian filter evasion."""
    if not text:
        return {"detected": False, "severity": "NONE", "indicators": []}

    indicators = []

    # Matches unbroken letters between 15 and 50 characters
    gibberish_pattern = re.compile(r'\b[a-zA-Z]{15,50}\b')
    matches = gibberish_pattern.findall(text)

    for match in set(matches):
        if is_likely_gibberish(match):
            indicators.append(f"random_string:{match[:15]}...")

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No gibberish strings found", "indicators": []}

    severity = "HIGH" if len(indicators) >= 3 else "MEDIUM"

    return {
        "detected": True,
        "severity": severity,
        "reason": f"Randomized evasion strings detected ({len(indicators)} matched)",
        "indicators": indicators
    }


def detect_hidden_keyword_stuffing(soup):
    """Detects word-salad keyword stuffing in hidden HTML elements."""
    if not soup:
        return {"detected": False, "severity": "NONE", "indicators": []}

    indicators = []

    # 1. Analyze <title> tags for invisible word stuffing
    titles = soup.find_all('title')
    for title in titles:
        word_count = len(title.get_text(strip=True).split())
        if word_count > 15:
            indicators.append(f"oversized_title_tag:{word_count}_words")

    # 2. Analyze CSS-hidden elements
    hidden_patterns = re.compile(
        r'(display:\s*none|visibility:\s*hidden|font-size:\s*0|opacity:\s*0|color:\s*(?:transparent|#fff|white))',
        re.IGNORECASE
    )
    hidden_elements = soup.find_all(style=hidden_patterns)

    for elem in hidden_elements:
        word_count = len(elem.get_text(strip=True).split())
        if word_count > 10:
            indicators.append(f"hidden_css_text:{word_count}_words")

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No hidden keyword stuffing detected",
                "indicators": []}

    severity = "HIGH" if len(indicators) >= 2 or any("oversized_title" in i for i in indicators) else "MEDIUM"

    return {
        "detected": True,
        "severity": severity,
        "reason": "Hidden HTML structures containing excessive text detected",
        "indicators": list(dict.fromkeys(indicators))
    }


def detect_url_mismatch(soup):
    """Detects when visible link text differs from the actual href destination."""
    if not soup:
        return {"detected": False, "severity": "NONE", "indicators": []}

    indicators = []
    links = soup.find_all('a', href=True)

    for link in links:
        href = link['href']
        visible_text = link.get_text(strip=True)

        if visible_text.startswith("http://") or visible_text.startswith("https://"):
            try:
                href_domain = urlparse(href).netloc
                visible_domain = urlparse(visible_text).netloc

                if href_domain and visible_domain and href_domain != visible_domain:
                    indicators.append(f"mismatch_target:{href_domain}")
            except Exception:
                continue

    if not indicators:
        return {"detected": False, "severity": "NONE", "reason": "No URL mismatches found", "indicators": []}

    return {
        "detected": True,
        "severity": "HIGH",
        "reason": "Visible URL text does not match the actual hyperlink destination",
        "indicators": list(dict.fromkeys(indicators))
    }