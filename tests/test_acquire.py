from repo_forensics.acquire import detect_license, is_remote, normalize_url, open_local, strip_credentials


def test_credentials_never_recorded():
    assert strip_credentials("https://user:ghp_secret@github.com/a/b.git") == "https://github.com/a/b.git"
    assert strip_credentials("git@github.com:a/b.git") == "git@github.com:a/b.git"


def test_remote_detection(tmp_path):
    assert is_remote("https://github.com/a/b") and is_remote("owner/name")
    assert normalize_url("owner/name") == "https://github.com/owner/name"
    assert not is_remote(str(tmp_path))


def test_license_detection(tmp_path):
    (tmp_path / "LICENSE").write_text("Apache License\nVersion 2.0, January 2004")
    assert detect_license(tmp_path, ["LICENSE"]) == ("Apache-2.0", "LICENSE")
    assert detect_license(tmp_path, []) == (None, None)


def test_local_non_git_directory_is_not_pinned(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    acq = open_local(tmp_path)
    assert not acq.is_git and acq.commit_sha is None
