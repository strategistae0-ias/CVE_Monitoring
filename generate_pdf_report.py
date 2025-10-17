import json
import os
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT

INPUT_JSON = "output/results.json"
OUTPUT_PDF = "output/cve-report.pdf"
NEW_IDS_PATH = "output/new_ids.txt"

# Ensure output folder exists
os.makedirs("output", exist_ok=True)

# Load JSON data
with open(INPUT_JSON, "r") as f:
    data = json.load(f)
    
# Styles
styles = getSampleStyleSheet()
wrap_style = ParagraphStyle(
    name='Wrap',
    fontSize=7,
    leading=9,
    alignment=TA_LEFT,
)

# Helpers
def format_row(entry):
    return [
        Paragraph(entry.get("sdk", "N/A"), wrap_style),
        Paragraph(entry.get("id", "N/A"), wrap_style),
        Paragraph(entry.get("severity", "N/A"), wrap_style),
        Paragraph(str(entry.get("cvss", "N/A")), wrap_style),
        Paragraph(entry.get("cwe", "N/A"), wrap_style),
        Paragraph(entry.get("published", "N/A").split("T")[0], wrap_style),
        Paragraph(entry.get("description", "N/A"), wrap_style),
    ]

def classify_entry(entry):
    row = format_row(entry)
    severity = entry.get("severity", "").upper()
    highlight = severity in {"HIGH", "CRITICAL"}
    return row, highlight

# Split entries
new_cves = []
existing_cves = []

for entry in data["results"]:
    formatted = classify_entry(entry)
    if entry.get("is_new", False):
        new_cves.append(formatted)
    else:
        existing_cves.append(formatted)

# PDF story
story = []

def add_table(title, entries, show_empty_note=False):
    story.append(Paragraph(f"<b>{title}</b>", styles["Heading2"]))
    story.append(Spacer(1, 8))

    if not entries and show_empty_note:
        story.append(Paragraph("No new CVEs detected.", styles["Normal"]))
        story.append(Spacer(1, 20))
        return

    header = [
        Paragraph(h, wrap_style) for h in
        ["SDK", "CVE ID", "Severity", "CVSS", "CWE", "Published", "Description"]
    ]
    data = [header] + [entry[0] for entry in entries]

    # Adjust column widths for A4 fit (~540 pts width total)
    col_widths = [60, 70, 50, 35, 60, 50, 165]

    table = Table(data, colWidths=col_widths, repeatRows=1)

    style = [
        ('GRID', (0, 0), (-1, -1), 0.25, colors.grey),
        ('BOX', (0, 0), (-1, -1), 0.25, colors.black),
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]

    # Highlight high/critical rows
    for idx, (_, highlight) in enumerate(entries, start=1):  # +1 for header
        if highlight:
            style.append(('TEXTCOLOR', (0, idx), (-1, idx), colors.red))

    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(Spacer(1, 20))


# Build full PDF
doc = SimpleDocTemplate(
    OUTPUT_PDF,
    pagesize=A4,
    leftMargin=10,
    rightMargin=10,
    topMargin=20,
    bottomMargin=20,
)

add_table("🚨 New CVEs", new_cves, show_empty_note=True)
add_table("📋 Existing CVEs", existing_cves)
doc.build(story)
print(f"✅ PDF report generated at: {OUTPUT_PDF}")
