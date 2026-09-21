"""Sample B2B Tax Invoice Generator using ReportLab."""

from pathlib import Path
from typing import List, Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors

from app.certs import DATA_DIR

INPUT_DIR = DATA_DIR / "input"

BUYERS = [
    {"name": "Acme Corporation India Pvt Ltd", "gstin": "06AAACA1234A1Z1", "city": "Gurugram"},
    {"name": "Bharat Logistics & Supply Chain Ltd", "gstin": "27AAACB5678B1Z2", "city": "Mumbai"},
    {"name": "Horizon Tech Solutions LLP", "gstin": "29AAACC9012C1Z3", "city": "Bengaluru"},
    {"name": "Apex Manufacturing Industries", "gstin": "07AAACD3456D1Z4", "city": "Delhi"},
    {"name": "Zenith Financial Services Ltd", "gstin": "33AAACE7890E1Z5", "city": "Chennai"},
    {"name": "Quantum Retail Ventures Pvt Ltd", "gstin": "36AAACF1234F1Z6", "city": "Hyderabad"},
    {"name": "Pinnacle Energy & Utilities Corp", "gstin": "24AAACG5678G1Z7", "city": "Ahmedabad"},
    {"name": "Starlight Global Logistics", "gstin": "19AAACH9012H1Z8", "city": "Kolkata"},
    {"name": "Vanguard Healthcare Solutions", "gstin": "08AAACI3456I1Z9", "city": "Jaipur"},
    {"name": "Nexus Telecommunications Pvt Ltd", "gstin": "09AAACJ7890J1Z0", "city": "Noida"},
]

ITEMS_CATALOG = [
    ("Cloud Infrastructure Services", "998313", 1, 20000.0),
    ("Enterprise API Digital Gateway", "998314", 1, 20000.0),
    ("Document Management System License", "998315", 1, 10000.0),
]


def create_invoice_pdf(file_path: Path, invoice_number: str, buyer: Dict[str, str]) -> None:
    """Creates a single uncompressed B2B tax invoice PDF."""
    file_path.parent.mkdir(parents=True, exist_ok=True)

    # IMPORTANT: pageCompression=0 so text bytes remain uncompressed for byte tampering inspection
    c = canvas.Canvas(str(file_path), pagesize=letter, pageCompression=0)
    width, height = letter

    # Outer border
    c.setStrokeColor(colors.HexColor("#CBD5E1"))
    c.setLineWidth(1)
    c.rect(36, 36, width - 72, height - 72)

    # Header Banner
    c.setFillColor(colors.HexColor("#0F172A"))
    c.rect(36, height - 106, width - 72, 70, fill=1, stroke=0)

    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 60, "DREAM ROAD TECHNOLOGIES PVT LTD")
    c.setFont("Helvetica", 9)
    c.drawString(50, height - 76, "GSTIN: 06AABCD1234E1Z5  |  CIN: U72900HR2022PTC101234")
    c.drawString(50, height - 89, "Cyber City, DLF Phase 2, Gurugram, Haryana - 122002, India")

    # Title
    c.setFillColor(colors.HexColor("#0F172A"))
    c.setFont("Helvetica-Bold", 12)
    c.drawRightString(width - 50, height - 130, "TAX INVOICE")
    c.setFont("Helvetica", 8)
    c.drawRightString(width - 50, height - 142, "(Under Rule 46 of CGST Rules, 2017)")

    # Invoice Details & Buyer Box
    c.setFillColor(colors.HexColor("#F8FAFC"))
    c.rect(50, height - 235, width - 100, 85, fill=1, stroke=1)

    c.setFillColor(colors.HexColor("#0F172A"))
    c.setFont("Helvetica-Bold", 9)
    c.drawString(60, height - 165, f"Invoice No: {invoice_number}")
    c.setFont("Helvetica", 9)
    c.drawString(60, height - 180, "Invoice Date: 2026-09-21")
    c.drawString(60, height - 195, "Place of Supply: Haryana (06)")
    c.drawString(60, height - 210, "Reverse Charge: No")

    c.setFont("Helvetica-Bold", 9)
    c.drawString(320, height - 165, "Billed To (Buyer):")
    c.setFont("Helvetica-Bold", 9)
    c.drawString(320, height - 180, buyer["name"])
    c.setFont("Helvetica", 9)
    c.drawString(320, height - 195, f"GSTIN: {buyer['gstin']}")
    c.drawString(320, height - 210, f"Address: Commercial Hub, {buyer['city']}, India")

    # Table Header
    y_table = height - 270
    c.setFillColor(colors.HexColor("#E2E8F0"))
    c.rect(50, y_table, width - 100, 20, fill=1, stroke=1)
    c.setFillColor(colors.HexColor("#1E293B"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(60, y_table + 6, "#")
    c.drawString(80, y_table + 6, "Item Description")
    c.drawString(280, y_table + 6, "HSN/SAC")
    c.drawRightString(360, y_table + 6, "Qty")
    c.drawRightString(440, y_table + 6, "Rate (Rs.)")
    c.drawRightString(width - 60, y_table + 6, "Amount (Rs.)")

    # Table Rows
    y = y_table - 22
    subtotal = 0.0
    c.setFont("Helvetica", 8)
    for idx, (desc, hsn, qty, rate) in enumerate(ITEMS_CATALOG, start=1):
        amt = qty * rate
        subtotal += amt
        c.drawString(60, y, str(idx))
        c.drawString(80, y, desc)
        c.drawString(280, y, hsn)
        c.drawRightString(360, y, str(qty))
        c.drawRightString(440, y, f"{rate:,.2f}")
        c.drawRightString(width - 60, y, f"{amt:,.2f}")
        y -= 20

    # Horizontal divider
    c.setStrokeColor(colors.HexColor("#E2E8F0"))
    c.line(50, y + 10, width - 50, y + 10)

    # Tax Calculation
    cgst = subtotal * 0.09
    sgst = subtotal * 0.09
    grand_total = subtotal + cgst + sgst

    y_tax = y - 5
    c.setFont("Helvetica", 8)
    c.drawString(300, y_tax, "Subtotal (Taxable Value):")
    c.drawRightString(width - 60, y_tax, f"Rs. {subtotal:,.2f}")

    y_tax -= 16
    c.drawString(300, y_tax, "Central GST (CGST @ 9%):")
    c.drawRightString(width - 60, y_tax, f"Rs. {cgst:,.2f}")

    y_tax -= 16
    c.drawString(300, y_tax, "State GST (SGST @ 9%):")
    c.drawRightString(width - 60, y_tax, f"Rs. {sgst:,.2f}")

    y_tax -= 24
    # Grand Total Banner
    c.setFillColor(colors.HexColor("#0F172A"))
    c.rect(280, y_tax - 6, width - 330, 24, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont("Helvetica-Bold", 10)
    # The exact string format required: "Total: Rs. 59,000.00"
    total_str = f"Total: Rs. {grand_total:,.2f}"
    c.drawString(290, y_tax + 2, total_str)

    # Payment info & Terms
    c.setFillColor(colors.HexColor("#475569"))
    c.setFont("Helvetica-Bold", 8)
    c.drawString(50, y_tax + 5, "Bank Account Details:")
    c.setFont("Helvetica", 8)
    c.drawString(50, y_tax - 10, "Bank: HDFC Bank Ltd  |  A/C No: 50200012345678")
    c.drawString(50, y_tax - 22, "IFSC: HDFC0000123  |  Branch: DLF Cyber City")

    # Bottom notice. Kept left of x=350 and nothing is drawn in the signature
    # box (360, 40, 560, 110): the stamp has a transparent background, so
    # anything underneath would print through it.
    c.setFont("Helvetica", 7.5)
    c.setFillColor(colors.HexColor("#64748B"))
    c.drawString(50, 72, "This is an electronic invoice issued under the")
    c.drawString(50, 61, "Information Technology Act, 2000. The digital")
    c.drawString(50, 50, "signature appears in the box on the right.")

    c.showPage()
    c.save()


def generate_sample_invoices(count: int = 10, input_dir: Path = INPUT_DIR) -> List[str]:
    """Generates `count` sample uncompressed invoices in `input_dir`."""
    input_dir.mkdir(parents=True, exist_ok=True)
    generated_files = []

    for i in range(1, count + 1):
        inv_num = f"INV-2026-{i:03d}"
        file_path = input_dir / f"{inv_num}.pdf"
        buyer = BUYERS[(i - 1) % len(BUYERS)]
        create_invoice_pdf(file_path, inv_num, buyer)
        generated_files.append(file_path.name)

    return generated_files
