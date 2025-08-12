import spacy
from spacy.tokens import Span
from spacy.matcher import Matcher
from flask import Flask, render_template, request, jsonify
import json

app = Flask(__name__)

# Load the large English model
nlp = spacy.load("en_core_web_lg")


class CybersecurityNER:
    def __init__(self, nlp_model):
        self.nlp = nlp_model
        self.matcher = Matcher(nlp_model.vocab)
        self.setup_patterns()

    def setup_patterns(self):
        """Define cybersecurity-specific patterns for custom NER"""

        # Vulnerability patterns
        vuln_patterns = [
            [{"LOWER": {"IN": ["cve", "vulnerability", "exploit", "zero-day", "0day"]}},
             {"IS_DIGIT": True, "OP": "?"},
             {"TEXT": "-", "OP": "?"},
             {"IS_DIGIT": True, "OP": "?"}],
            [{"LOWER": "sql"}, {"LOWER": "injection"}],
            [{"LOWER": "xss"}],
            [{"LOWER": "csrf"}],
            [{"LOWER": "buffer"}, {"LOWER": "overflow"}],
            [{"LOWER": "privilege"}, {"LOWER": "escalation"}],
            [{"LOWER": "remote"}, {"LOWER": "code"}, {"LOWER": "execution"}]
        ]

        # Threat actor patterns
        threat_patterns = [
            [{"LOWER": {"IN": ["apt", "advanced", "persistent", "threat"]}},
             {"IS_DIGIT": True, "OP": "?"}],
            [{"LOWER": {"IN": ["lazarus", "fancy", "bear", "cozy", "bear"]}},
             {"LOWER": "group", "OP": "?"}],
            [{"LOWER": {"IN": ["nation", "state"]}},
             {"LOWER": {"IN": ["actor", "threat", "attacker"]}}],
            [{"LOWER": {"IN": ["ransomware", "malware", "trojan", "botnet"]}},
             {"LOWER": "group", "OP": "?"}]
        ]

        # Security tools patterns
        tool_patterns = [
            [{"LOWER": {"IN": ["nmap", "wireshark", "metasploit", "burp", "suite"]}},
             {"LOWER": "suite", "OP": "?"}],
            [{"LOWER": {"IN": ["nessus", "openvas", "qualys", "rapid7"]}},
             {"LOWER": "scanner", "OP": "?"}],
            [{"LOWER": {"IN": ["splunk", "elk", "siem", "soar"]}},
             {"LOWER": "stack", "OP": "?"}],
            [{"LOWER": {"IN": ["ids", "ips", "firewall", "waf"]}},
             {"LOWER": "system", "OP": "?"}]
        ]

        # Infrastructure patterns
        infra_patterns = [
            [{"LOWER": {"IN": ["aws", "azure", "gcp", "cloud"]}},
             {"LOWER": {"IN": ["security", "infrastructure"]}, "OP": "?"}],
            [{"LOWER": "kubernetes"}, {"LOWER": {"IN": ["cluster", "security"]}, "OP": "?"}],
            [{"LOWER": "docker"}, {"LOWER": {"IN": ["container", "security"]}, "OP": "?"}],
            [{"LOWER": {"IN": ["vpn", "ssl", "tls", "https"]}},
             {"LOWER": {"IN": ["certificate", "encryption"]}, "OP": "?"}]
        ]

        # Add patterns to matcher
        self.matcher.add("VULNERABILITY", vuln_patterns)
        self.matcher.add("THREAT_ACTOR", threat_patterns)
        self.matcher.add("SECURITY_TOOL", tool_patterns)
        self.matcher.add("INFRASTRUCTURE", infra_patterns)

    def extract_entities(self, text):
        """Extract cybersecurity entities from text"""
        doc = self.nlp(text)
        matches = self.matcher(doc)

        # Convert matches to custom entities
        custom_entities = []
        for match_id, start, end in matches:
            label = self.nlp.vocab.strings[match_id]
            span = doc[start:end]
            custom_entities.append({
                "text": span.text,
                "label": label,
                "start": span.start_char,
                "end": span.end_char
            })

        # Include standard spaCy entities that might be relevant
        standard_entities = []
        for ent in doc.ents:
            if ent.label_ in ["ORG", "PERSON", "GPE", "PRODUCT", "EVENT"]:
                standard_entities.append({
                    "text": ent.text,
                    "label": ent.label_,
                    "start": ent.start_char,
                    "end": ent.end_char
                })

        return {
            "custom_entities": custom_entities,
            "standard_entities": standard_entities,
            "tokens": [token.lemma_ for token in doc if not token.is_stop],
            "sentiment": self.get_sentiment(doc)
        }

    def get_sentiment(self, doc):
        """Simple sentiment analysis based on cybersecurity context"""
        negative_indicators = ["breach", "attack", "malware", "vulnerability",
                               "threat", "compromised", "infected", "exploit"]
        urgent_indicators = ["critical", "emergency", "immediate", "urgent",
                             "zero-day", "active", "ongoing"]

        text_lower = doc.text.lower()
        negative_score = sum(1 for word in negative_indicators if word in text_lower)
        urgent_score = sum(1 for word in urgent_indicators if word in text_lower)

        if urgent_score > 0:
            return {"label": "URGENT", "confidence": min(urgent_score * 0.3, 1.0)}
        elif negative_score > 0:
            return {"label": "CONCERNING", "confidence": min(negative_score * 0.2, 1.0)}
        else:
            return {"label": "NEUTRAL", "confidence": 0.1}


class CybersecurityQueryRouter:
    def __init__(self, ner_system):
        self.ner = ner_system

    def analyze_query(self, text):
        """Analyze user query and determine response type"""
        entities = self.ner.extract_entities(text)
        query_type = self.classify_query(entities, text)
        response = self.generate_mock_response(query_type, entities, text)

        return {
            "entities": entities,
            "query_type": query_type,
            "response": response,
            "routing_explanation": self.explain_routing(query_type, entities)
        }

    def classify_query(self, entities, text):
        """Classify the type of cybersecurity query"""
        custom_entities = entities["custom_entities"]
        text_lower = text.lower()

        # Check for specific query patterns
        if any(ent["label"] == "VULNERABILITY" for ent in custom_entities):
            if any(word in text_lower for word in ["patch", "fix", "remediate"]):
                return "VULNERABILITY_REMEDIATION"
            else:
                return "VULNERABILITY_LOOKUP"

        elif any(ent["label"] == "THREAT_ACTOR" for ent in custom_entities):
            return "THREAT_INTELLIGENCE"

        elif any(ent["label"] == "SECURITY_TOOL" for ent in custom_entities):
            if any(word in text_lower for word in ["configure", "setup", "install"]):
                return "TOOL_CONFIGURATION"
            else:
                return "TOOL_INFORMATION"

        elif any(ent["label"] == "INFRASTRUCTURE" for ent in custom_entities):
            return "INFRASTRUCTURE_SECURITY"

        elif any(word in text_lower for word in ["incident", "breach", "attack", "compromise"]):
            return "INCIDENT_RESPONSE"

        elif any(word in text_lower for word in ["compliance", "audit", "policy", "framework"]):
            return "COMPLIANCE_QUERY"

        else:
            return "GENERAL_SECURITY"

    def generate_mock_response(self, query_type, entities, text):
        """Generate mock database/AI agent responses"""
        responses = {
            "VULNERABILITY_LOOKUP": self.mock_vuln_lookup(entities),
            "VULNERABILITY_REMEDIATION": self.mock_vuln_remediation(entities),
            "THREAT_INTELLIGENCE": self.mock_threat_intel(entities),
            "TOOL_CONFIGURATION": self.mock_tool_config(entities),
            "TOOL_INFORMATION": self.mock_tool_info(entities),
            "INFRASTRUCTURE_SECURITY": self.mock_infra_security(entities),
            "INCIDENT_RESPONSE": self.mock_incident_response(entities),
            "COMPLIANCE_QUERY": self.mock_compliance(entities),
            "GENERAL_SECURITY": self.mock_general_security(entities)
        }

        return responses.get(query_type, "Unable to process query.")

    def mock_vuln_lookup(self, entities):
        vulns = [ent for ent in entities["custom_entities"] if ent["label"] == "VULNERABILITY"]
        if vulns:
            vuln = vulns[0]["text"]
            return f"🔍 Database Query Result:\n\nVulnerability: {vuln}\nCVSS Score: 8.1 (High)\nAffected Systems: 47 assets in your environment\nFirst Discovered: 2024-01-15\nStatus: Patch available\n\nRecommendation: Priority patching required within 72 hours."
        return "No specific vulnerability found in query."

    def mock_vuln_remediation(self, entities):
        return "🛠️ AI Agent Response:\n\nRemediation steps identified:\n1. Download patch KB2024-001 from vendor portal\n2. Test in staging environment (estimated 2-4 hours)\n3. Schedule maintenance window for production deployment\n4. Verify patch installation with vulnerability scanner\n\nWould you like me to create a remediation ticket and notify the infrastructure team?"

    def mock_threat_intel(self, entities):
        actors = [ent for ent in entities["custom_entities"] if ent["label"] == "THREAT_ACTOR"]
        if actors:
            actor = actors[0]["text"]
            return f"🕵️ Threat Intelligence Database:\n\n{actor.upper()} Profile:\nTTP Classification: Nation-state actor\nPrimary Targets: Financial services, Healthcare\nRecent Activity: 3 campaigns detected in last 30 days\nIOCs: 127 indicators available\nAttribution Confidence: High (85%)\n\nRecommended Actions: Review IOC feeds, enhance monitoring for TTPs."
        return "General threat intelligence data available."

    def mock_tool_config(self, entities):
        tools = [ent for ent in entities["custom_entities"] if ent["label"] == "SECURITY_TOOL"]
        if tools:
            tool = tools[0]["text"]
            return f"⚙️ Configuration Assistant:\n\nTool: {tool.upper()}\nConfiguration Templates: 12 available\nBest Practice Policies: Enterprise security baseline\nDeployment Time: ~2-3 hours\nPrerequisites: Admin access, network segmentation\n\nShall I generate the configuration file and deployment checklist?"
        return "Tool configuration guidance available."

    def mock_tool_info(self, entities):
        return "📊 Tool Information Database:\n\nTool capabilities, licensing, compatibility matrix available.\nIntegration guides for SIEM, SOAR platforms included.\nPerformance benchmarks and sizing recommendations ready.\n\nAccessing detailed documentation..."

    def mock_infra_security(self, entities):
        return "🏗️ Infrastructure Security Assessment:\n\nCloud Security Posture: 23 misconfigurations found\nCompliance Status: 87% SOC2 compliant\nSecurity Groups: 156 rules requiring review\nEncryption Status: 12 unencrypted resources identified\n\nGenerating remediation priorities based on risk score..."

    def mock_incident_response(self, entities):
        return "🚨 Incident Response Protocol:\n\nSeverity: HIGH\nPlaybook: IR-2024-BREACH activated\nResponse Team: Notified (ETA 15 minutes)\nContainment: Automated isolation initiated\nForensics: Evidence preservation in progress\n\nNext steps: Stakeholder notification, regulatory requirements assessment."

    def mock_compliance(self, entities):
        return "📋 Compliance Database:\n\nFramework Mapping: NIST, ISO27001, SOX available\nControl Status: 142/156 controls implemented\nAudit Timeline: Q2 external audit scheduled\nGap Analysis: 14 high-priority gaps identified\n\nGenerating compliance dashboard and remediation roadmap..."

    def mock_general_security(self, entities):
        return "🛡️ General Security Information:\n\nSecurity posture overview, best practices, and current threat landscape available.\nRecommendations based on your environment and industry vertical.\n\nRouting to specialized AI agent for detailed analysis..."

    def explain_routing(self, query_type, entities):
        custom_count = len(entities["custom_entities"])
        sentiment = entities["sentiment"]["label"]

        explanation = f"Query classified as {query_type.replace('_', ' ').title()} based on:\n"
        explanation += f"• {custom_count} cybersecurity entities detected\n"
        explanation += f"• Sentiment analysis: {sentiment}\n"

        if custom_count > 0:
            entity_types = list(set(ent["label"] for ent in entities["custom_entities"]))
            explanation += f"• Entity types: {', '.join(entity_types)}\n"

        if sentiment == "URGENT":
            explanation += "• Routed to priority incident response system"
        elif query_type.startswith("VULNERABILITY"):
            explanation += "• Routed to vulnerability management database"
        elif query_type == "THREAT_INTELLIGENCE":
            explanation += "• Routed to threat intelligence platform"
        else:
            explanation += "• Routed to general security knowledge base"

        return explanation


# Initialize systems
cybersec_ner = CybersecurityNER(nlp)
query_router = CybersecurityQueryRouter(cybersec_ner)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    text = data.get('text', '')

    if not text:
        return jsonify({'error': 'No text provided'}), 400

    try:
        analysis = query_router.analyze_query(text)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
