from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
import time
import os

def generate_report(vulns, filename="report.pdf"):
    filepath = f"reports/{filename}"
    c = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4
    
    c.setFont("Helvetica-Bold", 16)
    c.drawString(1*inch, height - 1*inch, "AI-Assisted SOC Triage Report")
    c.setFont("Helvetica", 10)
    c.drawString(1*inch, height - 1.3*inch, f"Generated: {time.ctime()}")
    c.drawString(1*inch, height - 1.6*inch, f"Total Verified Threats: {len(vulns)}")
    
    y = height - 2.2*inch
    c.line(1*inch, y, 7.5*inch, y)
    y -= 0.3*inch
    
    if len(vulns) == 0:
        c.drawString(1*inch, y, "No verified threats found. Environment looks clean.")
    else:
        c.setFont("Helvetica-Bold", 12)
        c.drawString(1*inch, y, "Top Critical Findings (Prioritized)")
        y -= 0.4*inch
        
        for idx, v in enumerate(vulns[:10]):
            if y < 1*inch:
                c.showPage()
                y = height - 1*inch
                
            c.setFont("Helvetica-Bold", 10)
            c.drawString(1*inch, y, f"{idx+1}. {v['cve']} | Score: {v.get('priority_score', 0)}/10")
            y -= 0.2*inch
            c.setFont("Helvetica", 9)
            c.drawString(1.2*inch, y, f"Host: {v['host']} | Port: {v['port']} | Verdict: {v.get('final_verdict', 'N/A')}")
            y -= 0.15*inch
            c.drawString(1.2*inch, y, f"Confidence: {v.get('confidence', 0)}%")
            y -= 0.25*inch
            c.line(1.2*inch, y, 7.5*inch, y)
            y -= 0.2*inch
    
    c.save()
    return filepath
