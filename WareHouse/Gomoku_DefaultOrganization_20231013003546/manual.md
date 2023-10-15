# Cybersecurity Application User Manual

## Introduction
The Cybersecurity Application is a robust software solution designed to analyze a designated folder containing saved emails and identify potential threats. It employs the VirusTotal API to validate any suspicious elements discovered during the evaluation process. The application ensures accurate threat identification and generates a comprehensive report detailing the findings. The primary objective is to assess the security risks associated with the provided emails effectively.

## Installation
To use the Cybersecurity Application, follow these steps:

1. Install Python: Ensure that Python is installed on your system. You can download Python from the official website: https://www.python.org/downloads/

2. Clone the repository: Clone the repository containing the application code to your local machine.

3. Install dependencies: Open a terminal or command prompt, navigate to the cloned repository directory, and run the following command to install the required dependencies:

   ```
   pip install -r requirements.txt
   ```

4. Obtain a VirusTotal API key: Sign up for a VirusTotal account and obtain an API key. The API key is required for threat validation. You can sign up for a free account and obtain the API key from the VirusTotal website: https://www.virustotal.com/

## Usage
To use the Cybersecurity Application, follow these steps:

1. Open a terminal or command prompt and navigate to the cloned repository directory.

2. Run the application: Execute the following command to start the application:

   ```
   python main.py
   ```

3. Select a folder: Click on the "Select Folder" button in the application's GUI to choose the folder containing the saved emails for analysis.

4. Analysis and report generation: The application will analyze the emails in the selected folder and generate a comprehensive report detailing the identified threats. The report will include information about the threats, their severity, and any additional details obtained from the VirusTotal API.

5. View the report: After the analysis is complete, a separate window will open displaying the generated report. The report will be presented in a read-only text format.

## Customization
The Cybersecurity Application can be customized according to your specific requirements. Here are a few possible customization options:

- Whitelist: You can modify the "whitelist.txt" file to add or remove domains from the whitelist. The whitelist is used to exclude certain URLs from threat validation.

- GUI: You can modify the GUI design and layout in the "main.py" file using the tkinter library. You can customize the window title, dimensions, and button text.

- Report format: If you want to change the format or content of the generated report, you can modify the "generate_report" method in the "email_analyzer.py" file. You can customize the report text, add additional information, or change the file format.

## Troubleshooting
If you encounter any issues while using the Cybersecurity Application, consider the following troubleshooting steps:

- Ensure that the folder you select for analysis contains valid email files with the ".eml" extension.

- Verify that you have provided a valid VirusTotal API key in the "email_analyzer.py" file.

- Check your internet connection to ensure that the application can communicate with the VirusTotal API.

- If you encounter any error messages or unexpected behavior, refer to the error messages displayed in the terminal or command prompt for more information.

If the issue persists, you can reach out to our support team for assistance.

## Conclusion
The Cybersecurity Application provides a reliable and efficient solution for assessing the security risks associated with saved emails. By employing the VirusTotal API, the application accurately identifies potential threats and generates a comprehensive report. With its user-friendly interface and customizable options, the application offers a powerful tool for cybersecurity analysis.