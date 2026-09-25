# EML Phishing & Obfuscation Detection Engine

A lightweight, high-performance Python detection engine designed to analyze `.eml` email source code for hidden keyword stuffing, Bayesian spam filter evasion, structural email obfuscation, and header authentication failures.


<img width="1146" height="241" alt="TableofDetections" src="https://github.com/user-attachments/assets/503ecfe7-446c-4a06-a370-33204df3274c" />

--- 


<img width="1332" height="188" alt="Singel detection desription" src="https://github.com/user-attachments/assets/7b2c3866-9aaa-464f-85b5-ca6e0f6e7b97" />



Built as a practical cybersecurity portfolio project, this engine focuses on **email source telemetry, MIME header parsing, HTML DOM analysis, heuristic detection logic, and analyst-friendly CLI alerting**.

---

## Threat Overview

Phishing threat actors frequently combine **sender spoofing** with **content obfuscation** to bypass automated Email Security Gateways (SEGs) and Bayesian spam filters:

* **Header Authentication Failures:** Invalidate or missing SPF, DKIM, or DMARC signatures, indicating domain spoofing or unauthorized sending infrastructure.
* **Oversized `<title>` Tags:** Injecting hundreds of benign, news-related, or dictionary words into `<title>` elements inside the HTML body. Email clients do not render this text to the end user, but automated filters ingest it to dilute the overall "spam score" of the message.
* **CSS Hide Techniques:** Hiding word salad inside invisible HTML containers using inline styles (`display:none`, `visibility:hidden`, `font-size:0`, `opacity:0`, or invisible font colors).
* **High-Entropy Random Strings:** Injecting randomized alphanumeric strings (e.g., `uxnfmxbgvhgsrpnaozparzjhby`) to break signature matching and frustrate hash-based email reputation lookups.
* **Hyperlink Target Mismatches:** Disguising malicious destinations by displaying a benign URL in the link text while directing the `href` attribute to a deceptive external domain.

---

## Architecture

```text
       .eml File Ingestion (Recursive CLI Scan)
                          |
                          v
         MIME & Payload Extraction (email library)
                          |
     +--------------------+--------------------+
     |                                         |
     v                                         v
Header Analysis (Authentication)        Body Payload Parsing
 (SPF / DKIM / DMARC Verification)    (BeautifulSoup4 DOM Tree)
     |                                         |
     |                     +-------------------+-------------------+
     |                     |                   |                   |
     v                     v                   v                   v
Authentication      Hidden Keyword      High-Entropy        Hyperlink Target
Failure Rules       Stuffing Rules      Evasion Rules        Mismatch Rules
     |                     |                   |                   |
     +---------------------+-------------------+-------------------+
                                   |
                                   v
                    Threat Probability Scoring (%)
                                   |
                                   v
             Rich CLI Alerts & Interactive Progress Bar

```

---

## Detection Heuristics

The engine evaluates email payloads using four core heuristic modules in `detector/rules.py`:

1. **Authentication Failure Analysis (`detect_auth_header_failures`)**
* Parses `Authentication-Results` and `Received-SPF` headers.
* Extracts and reports the pass/fail/softfail status of **SPF**, **DKIM**, and **DMARC**.


2. **Hidden Keyword Stuffing (`detect_hidden_keyword_stuffing`)**
* Inspects `<title>` tags inside the message body for excessive word counts (>15 words).
* Identifies CSS-hidden containers (`display:none`, `visibility:hidden`, `font-size:0`, `opacity:0`) containing word-salad strings designed to evade text classification.


3. **Gibberish & Evasion Strings (`detect_gibberish_strings`)**
* Scans raw text for high-entropy continuous strings (15–50 characters) with high character diversity (>8 unique characters).
* Flags randomized tracking hashes and anti-analysis noise.


4. **Hyperlink Target Mismatch (`detect_url_mismatch`)**
* Compares the domain displayed in anchor tag text (e.g., `[https://paypal.com](https://paypal.com)`) against the actual destination domain in the `href` attribute (e.g., `[http://malicious-phish.ru](http://malicious-phish.ru)`).



---

## Scoring System

The engine aggregates matched indicators to calculate an overall **Threat Score (%)**:

| Threat Score | Severity Tier | Indicator Weighting & Thresholds |
| --- | --- | --- |
| **70% – 99%** | **High** | Multiple explicit structural obfuscation techniques + authentication failures. |
| **40% – 69%** | **Medium** | Moderate indicator count (e.g., hidden CSS text or isolated auth softfail). |
| **1% – 39%** | **Low** | Minor single-indicator anomaly detected. |
| **0%** | **Clean** | No obfuscation, evasion, or auth failure heuristics triggered. |


---

## Sample Alert Output

```text
DETECTION: phish_sample.eml

Threat Score: 90%
Auth Check: SPF: FAIL | DKIM: FAIL | DMARC: FAIL

[HIGH] Email authentication failures detected (spf_failure, dkim_failure, dmarc_failure)
Indicators: spf_failure, dkim_failure, dmarc_failure

[HIGH] Hidden HTML structures containing excessive text detected
Indicators: oversized_title_tag:248_words

[HIGH] Randomized evasion strings detected (4 matched)
Indicators: random_string:nyponavguxnsznv..., random_string:uxnfmxbgvhgsrpn...

```

### Summary Table

<img width="1146" height="241" alt="TableofDetections" src="https://github.com/user-attachments/assets/503ecfe7-446c-4a06-a370-33204df3274c" />




```text
                               Detection Engine Summary                               
┌──────────────────┬──────────────┬────────────────────────────────┬─────────────────┐
│ File Name        │ Threat Score │ Auth Status (SPF | DKIM | DMARC)│ Primary...      │
├──────────────────┼──────────────┼────────────────────────────────┼─────────────────┤
│ phish_sample.eml │          90% │ SPF: FAIL | DKIM: FAIL | D...  │ spf_failure...  │
│ clean_sample.eml │           0% │ SPF: PASS | DKIM: PASS | D...  │ Clean           │
└──────────────────┴──────────────┴────────────────────────────────┴─────────────────┘

```

---

## Installation

Clone the repository and set up a Python virtual environment:

```bash
git clone https://github.com/NemKasza/phish-obfuscation-detector-engine.git
cd phish-obfuscation-detector-engine

python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

```

Install dependencies:

```bash
python3 -m pip install -r requirements.txt

```

---

## Usage

<img width="640" height="165" alt="usage helpscreen" src="https://github.com/user-attachments/assets/9125c3a7-d616-4d35-9e6d-75bb6709953b" />



Scan a directory containing `.eml` files:

```bash
python3 main.py -d data/samples

```

View CLI usage options:

```bash
python3 main.py --help

```

---


---

## Project Structure

```text
eml-detection-engine/
├── data/
│   └── samples/                 # Sample .eml files for testing
├── detector/
│   ├── __init__.py
│   └── rules.py                 # Core heuristic rules (auth headers, DOM, strings, URLs)
├── main.py                      # Recursive CLI runner, progress rendering, and scoring engine
├── README.md                    # Project documentation
└── requirements.txt             # Dependencies (beautifulsoup4, rich, pytest)

```
