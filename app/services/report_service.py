from __future__ import annotations
from fpdf import FPDF
from datetime import datetime
from io import BytesIO
import json

class ReportService:
    @staticmethod
    def generate_accounts_pdf(accounts_data: list, generated_by: str) -> bytes:
        pdf = FPDF()
        pdf.add_page()
        
        # Header
        pdf.set_font("helvetica", "B", 16)
        pdf.cell(0, 10, "XUD-BANK - Rapport de Situation Financière", ln=True, align="C")
        
        pdf.set_font("helvetica", "", 10)
        pdf.cell(0, 10, f"Généré le : {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align="C")
        pdf.cell(0, 10, f"Par : {generated_by}", ln=True, align="C")
        pdf.ln(10)
        
        # Table Header
        pdf.set_fill_color(240, 240, 240)
        pdf.set_font("helvetica", "B", 9)
        pdf.cell(40, 8, "ID Compte", border=1, fill=True)
        pdf.cell(60, 8, "Titulaire", border=1, fill=True)
        pdf.cell(30, 8, "Solde (XOF)", border=1, fill=True)
        pdf.cell(30, 8, "Classification", border=1, fill=True)
        pdf.cell(30, 8, "Date Création", border=1, fill=True, ln=True)
        
        # Table Body
        pdf.set_font("helvetica", "", 8)
        for acc in accounts_data:
            pdf.cell(40, 8, str(acc['id_compte']), border=1)
            pdf.cell(60, 8, str(acc['titulaire']), border=1)
            pdf.cell(30, 8, f"{acc['solde']:,.2f}", border=1)
            pdf.cell(30, 8, str(acc['classification']), border=1)
            date_str = acc['created_at'].strftime('%d/%m/%Y') if hasattr(acc['created_at'], 'strftime') else str(acc['created_at'])
            pdf.cell(30, 8, date_str, border=1, ln=True)
            
        return pdf.output()
