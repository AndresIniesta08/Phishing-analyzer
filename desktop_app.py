"""Optional desktop interface for the phishing analyzer."""

from __future__ import annotations

import tkinter as tk
from tkinter import filedialog, messagebox

from phishing_analyzer import analyze_email


class PhishingAnalyzerApp:
    BACKGROUND = "#eef1ed"
    INK = "#183a34"
    MUTED = "#64736d"
    WHITE = "#ffffff"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Email Phishing Risk Analyzer")
        root.geometry("900x760")
        root.minsize(700, 620)
        root.configure(bg=self.BACKGROUND)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        header = tk.Frame(root, bg=self.INK, padx=28, pady=20)
        header.grid(row=0, column=0, sticky="ew")
        tk.Label(
            header,
            text="EMAIL SECURITY / MESSAGE REVIEW",
            bg=self.INK,
            fg="#a8d5bb",
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Phishing risk analyzer",
            bg=self.INK,
            fg=self.WHITE,
            font=("Segoe UI", 22, "bold"),
        ).pack(anchor="w", pady=(5, 0))

        main = tk.Frame(root, bg=self.BACKGROUND, padx=28, pady=20)
        main.grid(row=1, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=3)
        main.rowconfigure(4, weight=2)

        input_heading = tk.Frame(main, bg=self.BACKGROUND)
        input_heading.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        input_heading.columnconfigure(0, weight=1)
        tk.Label(
            input_heading,
            text="EMAIL MESSAGE",
            bg=self.BACKGROUND,
            fg=self.INK,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")
        tk.Button(
            input_heading,
            text="Open email file",
            command=self.open_file,
            font=("Segoe UI", 9),
            bg=self.WHITE,
            fg=self.INK,
            relief="solid",
            bd=1,
            padx=12,
            pady=6,
            cursor="hand2",
        ).grid(row=0, column=1, sticky="e")

        input_panel = tk.Frame(main, bg=self.WHITE, highlightthickness=1, highlightbackground="#d6ded8")
        input_panel.grid(row=1, column=0, sticky="nsew")
        input_panel.rowconfigure(0, weight=1)
        input_panel.columnconfigure(0, weight=1)
        self.email_input = tk.Text(
            input_panel,
            wrap="word",
            undo=True,
            font=("Consolas", 10),
            bg=self.WHITE,
            fg="#25352f",
            insertbackground=self.INK,
            relief="flat",
            padx=14,
            pady=12,
        )
        self.email_input.grid(row=0, column=0, sticky="nsew")
        input_scroll = tk.Scrollbar(input_panel, command=self.email_input.yview)
        input_scroll.grid(row=0, column=1, sticky="ns")
        self.email_input.configure(yscrollcommand=input_scroll.set)
        self.email_input.insert("1.0", "Paste the full email message here, including headers when available.")

        actions = tk.Frame(main, bg=self.BACKGROUND)
        actions.grid(row=2, column=0, sticky="ew", pady=12)
        tk.Button(
            actions,
            text="Analyze message",
            command=self.analyze,
            font=("Segoe UI", 10, "bold"),
            bg="#16745b",
            fg=self.WHITE,
            activebackground="#125e4a",
            activeforeground=self.WHITE,
            relief="flat",
            padx=18,
            pady=10,
            cursor="hand2",
        ).pack(side="left")
        tk.Button(
            actions,
            text="Clear",
            command=self.clear,
            font=("Segoe UI", 9),
            bg=self.BACKGROUND,
            fg=self.MUTED,
            relief="flat",
            padx=14,
            pady=10,
            cursor="hand2",
        ).pack(side="left", padx=(6, 0))
        tk.Label(
            actions,
            text="Offline check · links are never opened",
            bg=self.BACKGROUND,
            fg=self.MUTED,
            font=("Segoe UI", 9),
        ).pack(side="right", pady=10)

        tk.Label(
            main,
            text="ASSESSMENT",
            bg=self.BACKGROUND,
            fg=self.INK,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=3, column=0, sticky="w", pady=(4, 8))

        result_panel = tk.Frame(main, bg=self.WHITE, highlightthickness=1, highlightbackground="#d6ded8")
        result_panel.grid(row=4, column=0, sticky="nsew")
        result_panel.columnconfigure(0, weight=1)
        result_panel.rowconfigure(1, weight=1)

        self.risk_banner = tk.Frame(result_panel, bg="#edf2ee", padx=16, pady=12)
        self.risk_banner.grid(row=0, column=0, sticky="ew")
        self.risk_banner.columnconfigure(0, weight=1)
        self.risk_label = tk.Label(
            self.risk_banner,
            text="READY TO ANALYZE",
            bg="#edf2ee",
            fg=self.INK,
            font=("Segoe UI", 13, "bold"),
        )
        self.risk_label.grid(row=0, column=0, sticky="w")
        self.score_label = tk.Label(
            self.risk_banner,
            text="-- / 100",
            bg="#edf2ee",
            fg=self.INK,
            font=("Segoe UI", 11, "bold"),
        )
        self.score_label.grid(row=0, column=1, sticky="e")

        self.findings = tk.Text(
            result_panel,
            height=7,
            wrap="word",
            state="disabled",
            font=("Segoe UI", 10),
            bg=self.WHITE,
            fg="#25352f",
            relief="flat",
            padx=16,
            pady=12,
        )
        self.findings.grid(row=1, column=0, sticky="nsew")
        result_scroll = tk.Scrollbar(result_panel, command=self.findings.yview)
        result_scroll.grid(row=1, column=1, sticky="ns")
        self.findings.configure(yscrollcommand=result_scroll.set)
        self._set_findings("Your results and the reasons behind them will appear here.")

        tk.Label(
            main,
            text="Heuristic results are not a guarantee. Verify unexpected requests through a trusted channel.",
            bg=self.BACKGROUND,
            fg=self.MUTED,
            font=("Segoe UI", 9),
        ).grid(row=5, column=0, sticky="w", pady=(10, 0))

    def _set_findings(self, text: str) -> None:
        self.findings.configure(state="normal")
        self.findings.delete("1.0", "end")
        self.findings.insert("1.0", text)
        self.findings.configure(state="disabled")

    def open_file(self) -> None:
        filename = filedialog.askopenfilename(
            title="Open an email message",
            filetypes=(("Email and text files", "*.eml *.txt"), ("All files", "*.*")),
        )
        if not filename:
            return
        try:
            with open(filename, encoding="utf-8", errors="replace") as email_file:
                content = email_file.read()
        except OSError as exc:
            messagebox.showerror("Could not open file", str(exc), parent=self.root)
            return
        self.email_input.delete("1.0", "end")
        self.email_input.insert("1.0", content)

    def analyze(self) -> None:
        try:
            result = analyze_email(self.email_input.get("1.0", "end-1c"))
        except ValueError as exc:
            messagebox.showwarning("Email needed", str(exc), parent=self.root)
            return

        palette = {
            "LOW": ("#e5f3ea", "#176642"),
            "SUSPICIOUS": ("#fff1d6", "#8a5b00"),
            "HIGH": ("#fbe7e4", "#a32f24"),
        }
        background, foreground = palette[str(result["level"])]
        self.risk_banner.configure(bg=background)
        self.risk_label.configure(
            text=f"{result['level']} RISK  |  {result['subject']}",
            bg=background,
            fg=foreground,
        )
        self.score_label.configure(
            text=f"{result['score']} / 100  |  {result['url_count']} URL(s)",
            bg=background,
            fg=foreground,
        )
        findings_text = "\n\n".join(
            f"-  {finding.reason}" + (f"  (+{finding.points})" if finding.points else "")
            for finding in result["findings"]
        )
        self._set_findings(findings_text)

    def clear(self) -> None:
        self.email_input.delete("1.0", "end")
        self.risk_banner.configure(bg="#edf2ee")
        self.risk_label.configure(text="READY TO ANALYZE", bg="#edf2ee", fg=self.INK)
        self.score_label.configure(text="-- / 100", bg="#edf2ee", fg=self.INK)
        self._set_findings("Your results and the reasons behind them will appear here.")


def main() -> None:
    root = tk.Tk()
    PhishingAnalyzerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
