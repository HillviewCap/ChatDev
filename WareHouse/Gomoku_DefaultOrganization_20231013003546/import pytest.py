import pytest
from unittest.mock import patch
from email_analyzer import EmailAnalyzer

@pytest.fixture
def email_analyzer():
    return EmailAnalyzer("test_api_key")

# Happy path tests

@pytest.mark.parametrize(
    "folder_path, expected_emails",
    [
        ("test_folder1", ["email1.eml", "email2.eml"]),
        ("test_folder2", ["email3.eml"]),
    ],
    ids=["multiple_emails", "single_email"]
)
def test_analyze_emails_happy_path(email_analyzer, folder_path, expected_emails):
    email_analyzer.get_emails_from_folder = lambda path: expected_emails
    email_analyzer.analyze_threats = lambda: None

    email_analyzer.analyze_emails(folder_path)

    assert email_analyzer.emails == expected_emails

@pytest.mark.parametrize(
    "email, expected_urls",
    [
        ("This is a test email with a URL: https://example.com", ["https://example.com"]),
        ("No URLs in this email", []),
    ],
    ids=["with_url", "without_url"]
)
def test_extract_urls_happy_path(email_analyzer, email, expected_urls):
    urls = email_analyzer.extract_urls(email)

    assert urls == expected_urls

@pytest.mark.parametrize(
    "email, expected_threats",
    [
        ("This is a test email with a malicious URL: https://malicious.com", [{"url": "https://malicious.com", "positives": 5}]),
        ("This is a test email with a whitelisted URL: https://whitelisted.com", []),
    ],
    ids=["with_malicious_url", "with_whitelisted_url"]
)
def test_validate_threats_happy_path(email_analyzer, email, expected_threats):
    email_analyzer.extract_urls = lambda email: ["https://malicious.com", "https://whitelisted.com"]
    email_analyzer.is_whitelisted = lambda url, whitelist: url == "https://whitelisted.com"
    response_json = {"response_code": 1, "positives": 5}
    email_analyzer.requests.post = lambda url, params: MockResponse(response_json)

    threats = email_analyzer.validate_threats(email)

    assert threats == expected_threats

# Edge cases

def test_get_emails_from_folder_empty_folder(email_analyzer):
    folder_path = "empty_folder"

    emails = email_analyzer.get_emails_from_folder(folder_path)

    assert emails == []

def test_get_emails_from_folder_no_eml_files(email_analyzer):
    folder_path = "folder_without_eml_files"

    emails = email_analyzer.get_emails_from_folder(folder_path)

    assert emails == []

def test_get_emails_from_folder_nested_folders(email_analyzer):
    folder_path = "nested_folders"

    emails = email_analyzer.get_emails_from_folder(folder_path)

    assert emails == ["email1.eml", "email2.eml", "email3.eml"]

def test_analyze_threats_no_emails(email_analyzer):
    email_analyzer.emails = []

    email_analyzer.analyze_threats()

    assert email_analyzer.report == ""

def test_generate_report(email_analyzer):
    email_analyzer.report = "Test report"

    email_analyzer.generate_report()

    with open("report.txt", "r") as f:
        assert f.read() == "Test report"

# Error cases

def test_get_whitelist_file_not_found(email_analyzer):
    with patch("builtins.open", side_effect=FileNotFoundError):
        whitelist = email_analyzer.get_whitelist()

    assert whitelist == []

def test_is_whitelisted(email_analyzer):
    url = "https://whitelisted.com"
    whitelist = ["whitelisted.com"]

    is_whitelisted = email_analyzer.is_whitelisted(url, whitelist)

    assert is_whitelisted

class MockResponse:
    def __init__(self, json_data):
        self.json_data = json_data

    def json(self):
        return self.json_data

@pytest.fixture(autouse=True)
def mock_requests_post(monkeypatch):
    def mock_post(url, params):
        return MockResponse({"response_code": 0})

    monkeypatch.setattr(requests, "post", mock_post)
