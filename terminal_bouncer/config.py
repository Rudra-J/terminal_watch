from dataclasses import dataclass


@dataclass
class Config:
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "llama3"
    allow_threshold: float = 0.7
    deny_threshold: float = 0.4
    max_retries: int = 3
    temperature: float = 0.1
    top_p: float = 0.9
    guard_dir: str = ".claude_guard"
