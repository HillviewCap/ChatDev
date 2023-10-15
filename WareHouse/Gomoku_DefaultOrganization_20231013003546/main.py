'''
This is the main file of the cybersecurity application.
It imports the necessary modules and starts the GUI.
'''
import tkinter as tk
from tkinter import filedialog
from email_analyzer import EmailAnalyzer
class Application(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cybersecurity Application")
        self.geometry("400x200")
        self.email_analyzer = EmailAnalyzer()
        self.select_folder_button = tk.Button(self, text="Select Folder", command=self.select_folder)
        self.select_folder_button.pack(pady=20)
    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.email_analyzer.analyze_emails(folder_path)
            self.email_analyzer.generate_report()
            self.show_report()
    def show_report(self):
        report_window = tk.Toplevel(self)
        report_window.title("Report")
        report_text = tk.Text(report_window)
        report_text.pack()
        report_text.insert(tk.END, self.email_analyzer.get_report())
        report_text.configure(state="disabled")
if __name__ == "__main__":
    app = Application()
    app.mainloop()