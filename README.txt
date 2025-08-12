# Cybersecurity NER Demo with SpaCy

A Flask web application demonstrating custom Named Entity Recognition (NER) for cybersecurity queries using SpaCy's en_core_web_lg model.

## Initial Setup and Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Step 1: Install Python Dependencies
```bash
pip install flask spacy
```

### Step 2: Install SpaCy Language Model
For SpaCy, follow the installation instructions here: 
https://github.com/explosion/spacy-models/releases/tag/en_core_web_lg-3.8.0

Or install directly via pip:
```bash
python -m spacy download en_core_web_lg
```

### Step 3: Project Structure
Ensure your project directory looks like this:
```
cybersec_ner/
├── main.py
├── README.txt
├── templates/
│   └── index.html
└── static/
    ├── css/
    │   └── style.css
    └── js/
        └── app.js
```

### Step 4: Run the Application
```bash
python main.py
```

Navigate to `http://localhost:5000` in your web browser.

## Understanding the NER Demo

### What is Named Entity Recognition (NER)?
NER is a natural language processing technique that identifies and classifies named entities in text into predefined categories. Standard NER might identify "Apple" as an organization or "New York" as a location.

### What This Demo Shows You

#### 1. Custom Entity Patterns
This demo extends SpaCy's capabilities by creating custom patterns for cybersecurity-specific entities:

**VULNERABILITY Entities:**
- CVE identifiers (CVE-2024-1234)
- Attack types (SQL injection, XSS, buffer overflow)
- Security flaws (zero-day, privilege escalation)

**THREAT_ACTOR Entities:**
- APT groups (APT29, Lazarus Group)
- Nation-state actors
- Cybercriminal organizations

**SECURITY_TOOL Entities:**
- Scanning tools (Nmap, Nessus, Burp Suite)
- SIEM platforms (Splunk, ELK stack)
- Security appliances (IDS, IPS, firewall)

**INFRASTRUCTURE Entities:**
- Cloud platforms (AWS, Azure, GCP)
- Container technologies (Docker, Kubernetes)
- Security protocols (VPN, SSL/TLS)

#### 2. How SpaCy Processing Works

**Tokenization:**
SpaCy breaks down your input text into individual tokens (words, punctuation, etc.) and processes each one. The demo shows you these processed tokens so you can see how SpaCy "understands" your text.

**Pattern Matching:**
The Matcher component uses predefined patterns to find cybersecurity entities. For example:
- [{"LOWER": "cve"}, {"IS_DIGIT": True}] matches "CVE-2024"
- [{"LOWER": "sql"}, {"LOWER": "injection"}] matches "SQL injection"

**Entity Classification:**
When patterns match, SpaCy creates entity spans and labels them with our custom categories.

#### 3. Intelligent Query Routing

The demo simulates how you might route different types of queries in a real system:

**Database Queries:** Simple lookups containing structured data keywords
- Example: "Show me all systems affected by CVE-2024-1234"
- Routes to: SQL database query

**AI Agent Queries:** Conversational requests or negative sentiment
- Example: "I'm frustrated with this security alert"
- Routes to: Empathetic AI agent

**Complex AI Queries:** Advanced analysis or generation tasks
- Example: "Generate a comprehensive security strategy"
- Routes to: Advanced LLM or CrewAI agents

#### 4. Sentiment Analysis for Cybersecurity Context

The demo includes cybersecurity-aware sentiment analysis:
- **URGENT:** Critical security terms (zero-day, breach, critical)
- **CONCERNING:** Security issues (malware, vulnerability, attack)
- **NEUTRAL:** Standard informational queries

#### 5. Mock Response Generation

Each query type generates a realistic mock response showing what a real cybersecurity database or AI agent might return:
- Vulnerability databases with CVSS scores and affected systems
- Threat intelligence with IOCs and attribution data
- Tool configuration with deployment checklists
- Incident response with containment procedures

### Try These Examples to See SpaCy in Action

1. **"Show me CVE-2024-0815 vulnerability details"**
   - Watch how SpaCy identifies "CVE-2024-0815" as a VULNERABILITY entity
   - See how it routes to vulnerability database lookup

2. **"Configure Nmap for network scanning"**
   - SpaCy recognizes "Nmap" as a SECURITY_TOOL entity
   - Routes to tool configuration system

3. **"APT29 latest threat intelligence report"**
   - Identifies "APT29" as a THREAT_ACTOR entity
   - Routes to threat intelligence platform

4. **"Critical breach in AWS infrastructure needs immediate response"**
   - Multiple entities: "AWS" (INFRASTRUCTURE), "breach" triggers URGENT sentiment
   - Routes to incident response system

### Key Learning Points

1. **Custom NER extends SpaCy's capabilities** beyond general entities to domain-specific needs
2. **Pattern matching** allows precise identification of technical terms and identifiers
3. **Entity-based routing** enables intelligent system decisions based on what SpaCy finds
4. **Preprocessing pipeline** shows the complete flow from raw text to structured understanding
5. **Real-world applications** demonstrate how NLP preprocessing enables smart routing in production systems

### Extending the Demo

To add your own entity types:
1. Define new patterns in the `setup_patterns()` method
2. Add new routing logic in `classify_query()`
3. Create mock responses in `generate_mock_response()`
4. Update the CSS for new entity styling

This demonstrates the power of SpaCy for building domain-specific NLP systems that can intelligently understand and route specialized technical queries.

## Troubleshooting

### Common Issues

**SpaCy model not found:**
```
OSError: [E050] Can't find model 'en_core_web_lg'
```
Solution: Run `python -m spacy download en_core_web_lg`

**Flask not found:**
```
ModuleNotFoundError: No module named 'flask'
```
Solution: Run `pip install flask`

**Port already in use:**
```
OSError: [Errno 98] Address already in use
```
Solution: Kill existing Flask process or change port in main.py

### Verifying Installation
Test SpaCy installation:
```python
import spacy
nlp = spacy.load("en_core_web_lg")
doc = nlp("Test CVE-2024-1234 vulnerability")
print([(ent.text, ent.label_) for ent in doc.ents])
```

## Additional Resources

- SpaCy Documentation: https://spacy.io/
- Flask Documentation: https://flask.palletsprojects.com/
- Custom NER Training: https://spacy.io/usage/training#ner
- Pattern Matching: https://spacy.io/usage/rule-based-matching

## No Reason
Check out https://www.youtube.com/watch?v=EtIJUwkOAwM because this guy built an 8-bit computer using K'Nex