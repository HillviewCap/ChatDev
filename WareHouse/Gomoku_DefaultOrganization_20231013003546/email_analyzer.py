'''
This module contains the EmailAnalyzer class responsible for analyzing emails and generating the report.
It imports the necessary modules and uses the VirusTotal API for threat validation.
'''
import os
import json
import requests
import re

api_key = "f51ca30ed25271d0fa1271e18092b5195c87af19cba838fe02b76535282a8801"
class EmailAnalyzer:
    def __init__(self, api_key):
        self.emails = []
        self.report = ""
        self.api_key = api_key
    def analyze_emails(self, folder_path):
        self.emails = self.get_emails_from_folder(folder_path)
        self.analyze_threats()
    def get_emails_from_folder(self, folder_path):
        emails = []
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                if file.endswith(".eml"):
                    email_path = os.path.join(root, file)
                    with open(email_path, "r") as f:
                        email_content = f.read()
                        emails.append(email_content)
        return emails
    def analyze_threats(self):
        for email in self.emails:
            threats = self.validate_threats(email)
            self.report += f"Email: {email}\n"
            self.report += f"Threats: {threats}\n\n"
    def validate_threats(self, email):
        '''
        This method validates threats in an email using the VirusTotal API.
        It returns the number of threats detected or a message indicating failure.
        '''
        urls = self.extract_urls(email)
        api_url = "https://www.virustotal.com/vtapi/v2/url/scan"
        threats = []
        whitelist = self.get_whitelist()
        for url in urls:
            if self.is_whitelisted(url, whitelist):
                continue
            params = {"apikey": self.api_key, "url": url}
            response = requests.post(api_url, params=params)
            response_json = response.json()
            if response_json.get("response_code") == 1:
                threats.append({"url": url, "positives": response_json.get("positives")})
            else:
                threats.append({"url": url, "error": "Threat validation failed"})
        return threats
    def extract_urls(self, email):
        '''
        This method extracts URLs from the email content using regular expressions.
        '''
        urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", email)
        return urls
    def generate_report(self):
        with open("report.txt", "w") as f:
            f.write(self.report)
    def get_report(self):
        return self.report
    def get_whitelist(self):
        '''
        This method retrieves the whitelist of domains from a file.
        '''
        whitelist = []
        with open("whitelist.txt", "r") as f:
            for line in f:
                whitelist.append(line.strip())
        return whitelist
    def is_whitelisted(self, url, whitelist):
        '''
        This method checks if a URL is whitelisted.
        '''
        domain = url.split("//")[-1].split("/")[0]
        return domain in whitelist