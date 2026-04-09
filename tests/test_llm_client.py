from unittest.mock import patch, MagicMock
from terminal_bouncer.llm_client import build_prompt, reinforce_prompt, call_llm
from terminal_bouncer.config import Config


def test_build_prompt_includes_command():
    prompt = build_prompt("git push origin main")
    assert "git push origin main" in prompt

def test_build_prompt_includes_all_decision_values():
    prompt = build_prompt("ls")
    assert "ALLOW" in prompt
    assert "DENY" in prompt
    assert "ASK" in prompt

def test_build_prompt_includes_json_schema():
    prompt = build_prompt("ls")
    assert "confidence" in prompt
    assert "risk_level" in prompt
    assert "reason" in prompt

def test_reinforce_appends_to_original():
    original = build_prompt("ls")
    reinforced = reinforce_prompt(original, "bad output")
    assert original in reinforced
    assert len(reinforced) > len(original)

def test_reinforce_contains_strict_instruction():
    reinforced = reinforce_prompt("prompt", "bad output")
    assert "STRICT JSON" in reinforced

def test_call_llm_posts_to_ollama():
    config = Config()
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": '{"decision": "ALLOW"}'}
    mock_resp.raise_for_status = MagicMock()

    with patch("terminal_bouncer.llm_client.requests.post", return_value=mock_resp) as mock_post:
        result = call_llm("test prompt", config)

    assert result == '{"decision": "ALLOW"}'
    url = mock_post.call_args[0][0]
    assert config.ollama_url in url

def test_call_llm_sends_correct_model():
    config = Config(ollama_model="mistral")
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": "result"}
    mock_resp.raise_for_status = MagicMock()

    with patch("terminal_bouncer.llm_client.requests.post", return_value=mock_resp) as mock_post:
        call_llm("prompt", config)

    body = mock_post.call_args[1]["json"]
    assert body["model"] == "mistral"

def test_call_llm_uses_deterministic_params():
    config = Config(temperature=0.1, top_p=0.9)
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"response": "result"}
    mock_resp.raise_for_status = MagicMock()

    with patch("terminal_bouncer.llm_client.requests.post", return_value=mock_resp) as mock_post:
        call_llm("prompt", config)

    options = mock_post.call_args[1]["json"]["options"]
    assert options["temperature"] == 0.1
    assert options["top_p"] == 0.9
