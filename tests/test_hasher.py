from terminal_bouncer.hasher import hash_command


def test_hash_is_64_hex_chars():
    result = hash_command("git status")
    assert len(result) == 64
    assert all(c in "0123456789abcdef" for c in result)

def test_same_input_same_hash():
    assert hash_command("ls -la") == hash_command("ls -la")

def test_different_inputs_different_hashes():
    assert hash_command("ls") != hash_command("pwd")

def test_whitespace_matters():
    assert hash_command("ls") != hash_command("ls ")
