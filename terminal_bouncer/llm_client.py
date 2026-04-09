import requests
from terminal_bouncer.config import Config


_EVAL_TEMPLATE = """\
You are a security guard evaluating a shell command proposed by an AI assistant.

Command to evaluate: {command}

Respond with ONLY valid JSON in this exact format:
{{
  "decision": "ALLOW",
  "confidence": 0.9,
  "risk_level": "LOW",
  "reason": "specific reason here"
}}

Where:
- decision: "ALLOW" (safe to run), "DENY" (dangerous/malicious), or "ASK" (needs user confirmation)
- confidence: float between 0.0 and 1.0
- risk_level: "LOW", "MEDIUM", or "HIGH"
- reason: specific explanation, minimum 5 characters, not vague

Return ONLY the JSON object. No explanation, no markdown, no code blocks.\
"""

_REINFORCE_SUFFIX = """

Your previous output was invalid.

You MUST return STRICT JSON with:
- correct schema (decision, confidence, risk_level, reason)
- confidence as a float between 0.0 and 1.0
- decision must be exactly: ALLOW, DENY, or ASK
- risk_level must be exactly: LOW, MEDIUM, or HIGH
- reason must be specific (not vague) and at least 5 characters

DO NOT include any text outside the JSON object.\
"""


def build_prompt(command: str) -> str:
    return _EVAL_TEMPLATE.format(command=command)


def reinforce_prompt(prompt: str, bad_response: str) -> str:
    return prompt + _REINFORCE_SUFFIX


def call_llm(prompt: str, config: Config) -> str:
    """Send prompt to Ollama and return raw text response."""
    response = requests.post(
        f"{config.ollama_url}/api/generate",
        json={
            "model": config.ollama_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "top_p": config.top_p,
            },
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["response"]
