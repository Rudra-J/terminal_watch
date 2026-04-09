from terminal_bouncer.config import Config


def test_default_config():
    config = Config()
    assert config.ollama_url == "http://localhost:11434"
    assert config.ollama_model == "llama3"
    assert config.allow_threshold == 0.7
    assert config.deny_threshold == 0.4
    assert config.max_retries == 3
    assert config.temperature == 0.1
    assert config.top_p == 0.9
    assert config.guard_dir == ".claude_guard"


def test_custom_config():
    config = Config(ollama_model="mistral", allow_threshold=0.8)
    assert config.ollama_model == "mistral"
    assert config.allow_threshold == 0.8
    assert config.ollama_url == "http://localhost:11434"  # unchanged
