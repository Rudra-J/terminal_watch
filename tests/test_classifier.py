from terminal_bouncer.classifier import classify_command


def test_classifies_git():
    assert classify_command("git push origin main") == "GIT"

def test_classifies_git_status():
    assert classify_command("git status") == "GIT"

def test_classifies_pip():
    assert classify_command("pip install requests") == "INSTALL"

def test_classifies_pip3():
    assert classify_command("pip3 install flask") == "INSTALL"

def test_classifies_npm():
    assert classify_command("npm install express") == "INSTALL"

def test_classifies_yarn():
    assert classify_command("yarn add lodash") == "INSTALL"

def test_classifies_python():
    assert classify_command("python script.py") == "PYTHON"

def test_classifies_python3():
    assert classify_command("python3 -m pytest") == "PYTHON"

def test_classifies_rm():
    assert classify_command("rm -rf ./dist") == "FILE_OPS"

def test_classifies_cp():
    assert classify_command("cp file.txt /tmp/") == "FILE_OPS"

def test_classifies_curl():
    assert classify_command("curl https://api.example.com") == "NETWORK"

def test_classifies_wget():
    assert classify_command("wget https://example.com/file") == "NETWORK"

def test_classifies_other():
    assert classify_command("make build") == "OTHER"

def test_classifies_other_unknown():
    assert classify_command("some_custom_tool --flag") == "OTHER"
