from reportlab.lib.enums import TA_JUSTIFY, TA_RIGHT, TA_CENTER
from reportlab.lib.pdfencrypt import StandardEncryption
from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Table, TableStyle,
    Spacer, PageBreak, Image, Flowable, ListFlowable, ListItem
)
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from datetime import datetime
from io import BytesIO
import os

# Custom Flowable to add TOC entries during build
class TOCEntry(Flowable):
    def __init__(self, level, text, toc):
        Flowable.__init__(self)
        self.level = level
        self.text = text
        self.toc = toc
        
    def draw(self):
        page = self.canv.getPageNumber()
        self.toc.addEntry(self.level, self.text, page)
        
    def split(self, availWidth, availHeight):
        return []

def generate_pdf_report(project_name, vulnerabilities, severity_count, password=None, report_code="Repogen"):
    buffer = BytesIO()
    
    #sorting
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    
    # Sort vulnerabilities by severity 
    sorted_vulnerabilities = sorted(
        vulnerabilities, 
        key=lambda x: severity_order.get(x.get("severity", "LOW"), 4)
    )

    # Configure encryption
    encrypt_obj = None
    if password:
        encrypt_obj = StandardEncryption(password, canPrint=1, canCopy=0, canModify=0)

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=50,
        leftMargin=50,
        topMargin=50,
        bottomMargin=50,
        encrypt=encrypt_obj  # Add encryption
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="H1", fontSize=18, spaceAfter=20, spaceBefore=10, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="H2", fontSize=14, spaceAfter=12, spaceBefore=8, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="Body", fontSize=11, leading=18, spaceAfter=8, alignment=TA_JUSTIFY))

    story = []
    
    # Create the TableOfContents object
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [
        ParagraphStyle(name='TOCHeading1', fontSize=12, leftIndent=0, leading=16, 
                      fontName='Helvetica-Bold', spaceBefore=5, spaceAfter=5),
        ParagraphStyle(name='TOCHeading2', fontSize=11, leftIndent=20, leading=14,
                      fontName='Helvetica', spaceBefore=3, spaceAfter=3),
    ]

    
    # Helper function to add paragraphs with TOC entries
    def addPara(text, style, level=0):
        para = Paragraph(text, style)
        if level >= 0:  # Only add to TOC if level is non-negative
            # Add the TOC entry correctly with page number resolved during draw
            story.append(TOCEntry(level, text, toc))
            story.append(para)
        else:
            story.append(para)
        return para

    # -------- PAGE NUMBERS & BORDERS --------
    def footer(canvas, doc):
        # Draw watermark first (so it appears behind content)
        canvas.saveState()
        # Set watermark properties
        canvas.setFillColor(colors.Color(0.9, 0.9, 0.9, alpha=0.3))  # Light gray with transparency
        
        # Adjust font size based on code length
        font_size = 60 if len(report_code) > 10 else 80
        canvas.setFont("Helvetica-Bold", font_size)
        
        # Calculate center position for watermark
        page_width = A4[0]  # 595.27 points
        page_height = A4[1]  # 841.89 points
        
        # Rotate and draw watermark diagonally
        canvas.translate(page_width / 2, page_height / 2)
        canvas.rotate(45)
        canvas.drawCentredString(0, 0, report_code)
        canvas.restoreState()
        
        # Draw page border
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#333333"))
        canvas.setLineWidth(1)
        # Draw a rectangle border (x, y, width, height)
        # A4 page size is 595.27 x 841.89 points
        # Drawing border 30 points from edges
        canvas.rect(30, 30, 535.27, 781.89, stroke=1, fill=0)
        canvas.restoreState()
        
        # Draw page number
        canvas.setFont("Helvetica", 9)
        canvas.setFillColor(colors.grey)
        canvas.drawRightString(560, 20, f"Page {doc.page}")

    # ================= PAGE 1: TITLE =================
    # Add Date at top right
    today_date = datetime.now().strftime("%B %d, %Y")
    story.append(Paragraph(today_date, ParagraphStyle(name="TopRightDate", parent=styles['Normal'], alignment=TA_RIGHT, fontSize=10)))
    story.append(Spacer(1, 20))

    # Add logo
    logo_path = os.path.join(os.path.dirname(__file__), "assets", "repogen.png")
    if os.path.exists(logo_path):
        logo = Image(logo_path, width=350, height=350)
        logo.hAlign = 'CENTER'
        story.append(logo)
        story.append(Spacer(1, 30))
    
    story.append(Paragraph(project_name, styles["Title"]))
    story.append(Spacer(1, 30))
    
    # Add metadata with generation info and vulnerability count
    meta = Paragraph(
        f"Report ID: {report_code} | "
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"Total Vulnerabilities: {len(vulnerabilities)}",
        styles["Normal"]
    )
    story.append(meta)
    story.append(Spacer(1, 20))
    
    story.append(Spacer(1, 12))
    story.append(PageBreak())

    # ================= PAGE 2: TABLE OF CONTENTS =================
    story.append(Paragraph("Table of Contents", styles["H1"]))
    story.append(Spacer(1, 10))
    story.append(toc)
    story.append(PageBreak())


    # ================= PAGE 3: PROBLEM STATEMENT =================
    addPara("1. Problem Statement", styles["H1"], level=0)
    story.append(Spacer(1, 20))
    PROBLEM_STATEMENT_TEXT = """In many organizations, the creation of cybersecurity assessment reports relies heavily on manual processes. Vulnerability information is collected from multiple Excel sheets, and proof-of-concept (PoC) details are added manually to the reports. This approach makes the reporting process repetitive, time-consuming, and inefficient.
<br/><br/>
Manual reporting often leads to inconsistencies in report formats and structures, resulting in variations in quality. It is also prone to errors such as redundant vulnerability findings, incorrect risk classification, and missing or incomplete evidence. These issues can reduce the reliability and usefulness of cybersecurity reports.
<br/><br/>
Additionally, manual report preparation makes it difficult to scale or adapt the process when there are changes in vulnerability data or reporting formats. The lack of automation delays report delivery and negatively impacts productivity. Therefore, there is a clear need for a centralized and automated cybersecurity reporting system that ensures accuracy, consistency, scalability, and efficient report generation."""
    story.append(Paragraph(PROBLEM_STATEMENT_TEXT, styles["Body"]))
    story.append(Spacer(1, 20))
    story.append(PageBreak())
    
    # 1.1 Introduction
    addPara("1.1 Introduction", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This security assessment report documents the findings from a comprehensive evaluation "
        "of the target application's security posture. The assessment was designed to identify "
        "vulnerabilities, misconfigurations, and potential security risks.",
        styles["Body"]
    ))
    story.append(Spacer(1, 15))
    
    # 1.2 Scope
    addPara("1.2 Scope", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "The scope of this assessment encompasses all components of the target application, "
        "including web interfaces, APIs, mobile applications, and underlying infrastructure. "
        "Testing was conducted in accordance with the agreed-upon rules of engagement.",
        styles["Body"]
    ))
    story.append(Spacer(1, 15))
    
    # 1.3 Objective
    addPara("1.3 Objective", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "The primary objective of this assessment is to identify security vulnerabilities and "
        "provide actionable remediation guidance to enhance the overall security posture of the "
        "application and protect against potential threats.",
        styles["Body"]
    ))
    story.append(Spacer(1, 15))
    
    # 1.4 Executive Summary
    addPara("1.4 Executive Summary", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    EXECUTIVE_SUMMARY_TEXT = """This assessment was conducted to identify security vulnerabilities, configuration weaknesses, and potential exploitation vectors within the target application. The testing process involved a hybrid approach utilizing automated scanning tools and manual exploitation techniques based on the OWASP Top 10 and NIST frameworks.

The assessment identified multiple security findings ranging from Critical to Low severity. The most significant risks observed involve improper input validation and access control mechanisms, which could allow unauthorized data access. Immediate remediation is recommended for all High and Critical findings to maintain the confidentiality, integrity, and availability of the system."""
    story.append(Paragraph(EXECUTIVE_SUMMARY_TEXT, styles["Body"]))
    story.append(Spacer(1, 15))
    
    # 1.5 Methodology
    addPara("1.5 Methodology", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    METHODOLOGY_TEXT = """The security assessment followed a structured methodology aligned with industry best practices:<br/>

1. Information Gathering: Passive and active reconnaissance to map the application structure.<br/>
2. Threat Modeling: Identifying potential attack vectors based on business logic.<br/>
3. Vulnerability Analysis: Automated scanning using industry-standard tools (e.g., Burp Suite, Nessus).<br/>
4. Exploitation: Manual verification of vulnerabilities to eliminate false positives.<br/>
5. Reporting: Documentation of findings with risk ratings based on the CVSS v3.1 scoring system.<br/>

The assessment adhered to the OWASP Web Security Testing Guide (WSTG) and NIST SP 800-115 standards."""
    story.append(Paragraph(METHODOLOGY_TEXT, styles["Body"]))
    story.append(Spacer(1, 15))
    
    # 1.6 Testing
    addPara("1.6 Testing", styles["H2"], level=1)
    story.append(Spacer(1, 10))
    TESTING_TYPES_TEXT = """<b>Black Box Testing:</b><br/>
The assessment was conducted with zero prior knowledge of the internal infrastructure or source code. The testing team simulated an external attacker approach to identify vulnerabilities exposed to the public internet.<br/><br/>

<b>Gray Box Testing:</b><br/>
The assessment was performed with partial knowledge, including user credentials (authenticated testing). This approach focused on identifying privilege escalation and business logic flaws accessible to authorized users.<br/><br/>

<b>White Box Testing (Static Analysis):</b><br/>
A comprehensive assessment performed with full access to the source code, architecture diagrams, and access to the internal network. This allows for the identification of deep-seated logic flaws and secure coding violations that external scans might miss.<br/><br/>

<b>API Security Testing:</b><br/>
Focused evaluation of Application Programming Interfaces (REST/SOAP/GraphQL). Testing includes checking for Broken Object Level Authorization (BOLA), excessive data exposure, injection attacks, and improper asset management.<br/><br/>

<b>Network Infrastructure Assessment:</b><br/>
Evaluation of the underlying server and network configurations. This includes port scanning, service enumeration, checking for unpatched software versions, and verifying firewall rule effectiveness to prevent unauthorized network access.<br/><br/>

<b>Mobile Application Security Testing (MAST):</b><br/>
Analysis of mobile binaries (Android APK / iOS IPA) involving both static analysis (hardcoded secrets, insecure data storage) and dynamic analysis (runtime manipulation, SSL pinning bypass) to ensure the mobile client is secure."""
    story.append(Paragraph(TESTING_TYPES_TEXT, styles["Body"]))
    story.append(Spacer(1, 20))
    story.append(PageBreak())

    # ================= PAGE 4: LIST OF VULNERABILITIES =================
    addPara("2. List of Vulnerabilities", styles["H1"], level=0)
    story.append(Spacer(1, 15))

    table_data = [
        ["ID", "Severity", "CVSS", "Status", "Category"]
    ]

    for v in vulnerabilities:
        table_data.append([
            v["vuln_id"],
            v["severity"],
            v["cvss_score"],
            v["status"],
            v["category"]
        ])

    table = Table(table_data, colWidths=[60, 80, 60, 70, 180], rowHeights=25)
    style = [
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.whitesmoke),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
        ("ALIGN", (1,1), (-1,-1), "CENTER"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
    ]

    for i, v in enumerate(vulnerabilities, 1):
        SEVERITY_COLORS = {
            "CRITICAL": colors.HexColor("#bf0000"),
            "HIGH":     colors.HexColor("#ff0000"),
            "MEDIUM":   colors.HexColor("#ffc000"),
            "LOW":      colors.HexColor("#00b050"),
        }

        bg = SEVERITY_COLORS.get(v["severity"], colors.white)

        style.append(("BACKGROUND", (1,i), (1,i), bg))

    table.setStyle(TableStyle(style))
    story.append(table)
    story.append(Spacer(1, 20))
    story.append(PageBreak())

    # ================= PAGE 5: RISK MATRIX =================
    addPara("3. Risk Matrix", styles["H1"], level=0)
    story.append(Spacer(1, 15))

    risk_table = Table([
        ["Severity", "Count"],
        ["Critical", severity_count["CRITICAL"]],
        ["High", severity_count["HIGH"]],
        ["Medium", severity_count["MEDIUM"]],
        ["Low", severity_count["LOW"]],
    ], rowHeights=30)

    risk_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,1), (0,1), colors.HexColor("#bf0000")),
        ("BACKGROUND", (0,2), (0,2), colors.HexColor("#ff0000")),
        ("BACKGROUND", (0,3), (0,3), colors.HexColor("#ffc000")),
        ("BACKGROUND", (0,4), (0,4), colors.HexColor("#00b050")),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("FONT", (0,0), (-1,0), "Helvetica-Bold"),
    ]))
    risk_table.hAlign = 'CENTER'

    story.append(risk_table)
    story.append(Spacer(1, 30))
    
    # Add Pie Chart for Severity Distribution
    drawing = Drawing(400, 200)
    pie = Pie()
    pie.x = 150
    pie.y = 10
    
    pie.width = 150
    pie.height = 150
    
    # Prepare data for pie chart (only include non-zero counts)
    pie_data = []
    pie_labels = []
    pie_colors = []
    
    severity_data = [
        ("Critical", severity_count["CRITICAL"], colors.HexColor("#bf0000")),
        ("High", severity_count["HIGH"], colors.HexColor("#ff0000")),
        ("Medium", severity_count["MEDIUM"], colors.HexColor("#ffc000")),
        ("Low", severity_count["LOW"], colors.HexColor("#00b050"))
    ]
    
    total_vulns = sum(severity_count.values())
    for label, count, color in severity_data:
        if count > 0:
            percentage = (count / total_vulns * 100) if total_vulns > 0 else 0
            pie_data.append(count)
            pie_labels.append(f"{label}: {count} ({percentage:.1f}%)")
            pie_colors.append(color)
    
    pie.data = pie_data
    pie.labels = pie_labels
    pie.slices.strokeWidth = 0.5
    pie.slices.strokeColor = colors.white
    
    # Apply colors to each slice
    for i, color in enumerate(pie_colors):
        pie.slices[i].fillColor = color
    
    drawing.add(pie)
    drawing.hAlign = 'CENTER'
    story.append(drawing)
    story.append(Paragraph("<b>Figure 1: Vulnerability Severity Distribution</b>", 
                 ParagraphStyle(name="Caption", parent=styles["Normal"], alignment=1, fontSize=10, spaceBefore=10)))
    story.append(PageBreak())

    # ================= TECHNICAL FINDINGS =================
    addPara("4. Technical Findings", styles["H1"], level=0)
    story.append(Spacer(1, 10))
    
    for v in sorted_vulnerabilities:
        addPara(f"Vulnerability ID: {v['vuln_id']}", styles["H1"], level=1)
        story.append(Spacer(1, 15))

        meta = Table([
            ["Severity", v["severity"], "Status", v["status"]],
            ["CVSS Score", v["cvss_score"], "CVSS ID", v["cvss_id"]],
            ["Category", v["category"], "Affected Systems", v["affected_systems"]],
        ], colWidths=[90, 150, 120, 150], rowHeights=28)

        meta.setStyle(TableStyle([
            ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
            ("BACKGROUND", (1,0), (1,0),
             colors.HexColor("#d32f2f") if v["severity"]=="CRITICAL"
             else colors.HexColor("#f57c00") if v["severity"]=="HIGH"
             else colors.HexColor("#1976d2")
             if v["severity"]=="MEDIUM" else colors.HexColor("#388e3c")),
            ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
            ("FONT", (0,0), (0,-1), "Helvetica-Bold"),
        ]))

        story.append(meta)
        story.append(Spacer(1, 20))

        story.append(Paragraph("Findings", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["findings"], styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Impact", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["impact"], styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Remediation", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["remediation"], styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Affected Component", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["affected_component"], styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("URL", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["url"], styles["Body"]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Reference", styles["H2"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph(v["reference"], styles["Body"]))
        story.append(Spacer(1, 15))

        story.append(PageBreak())

    # ================= APPENDIX A =================
    addPara("5. APPENDIX A", styles["H1"], level=0)
    story.append(Spacer(1, 10))
    story.append(Paragraph("OWASP TOP 10 VULNERABILITIES", styles["H2"]))
    story.append(Spacer(1, 5))
    
    # OWASP Top 10 Table Data
    owasp_data = [
        ["Name", "Description"],
        ["A01 - Broken Access Control", 
         "Broken access control vulnerabilities occur when a user can access a resource or carry out an action that they should not have permission for. Such failures often result in unauthorized disclosure, alteration, or deletion of data, or the execution of a business operation beyond the user's authorized boundaries."],
        
        ["A02 - Cryptographic Failures", 
         "Cryptographic Failure is a vulnerability that occurs when sensitive data is not stored securely. Attackers may steal or modify such weakly protected data to conduct credit card fraud, identity theft, or other crimes."],
        
        ["A03 - Injection", 
         "Injection vulnerabilities, like SQL, OS, and LDAP injections, manifest when untrusted data is introduced to an interpreter as a component of a command or query. The malicious data supplied by the attacker can deceive the interpreter into executing unintended commands or gaining access to data without the necessary authorization."],
        
        ["A04 - Insecure Design", 
         "Insecure design primarily concerns the vulnerabilities stemming from design and architectural deficiencies, emphasizing the importance of practices such as threat modeling, secure design patterns, and principles. Exploiting insecure design involves attackers conducting threat modeling on software workflows to uncover a wide spectrum of vulnerabilities and weaknesses."],
        
        ["A05 - Security Misconfiguration", 
         "Good security requires having a secure configuration defined and deployed for the application, frameworks, application server, web server, database server, and platform. Secure settings should be defined, implemented, and maintained, as defaults are often insecure. Additionally, software should be kept up to date."],
        
        ["A06 - Vulnerable and Outdated Components", 
         "Components that are vulnerable or outdated, including libraries, frameworks, and other software modules, typically operate with extensive privileges. Exploiting a vulnerable component can lead to significant data loss or a takeover of the server. Applications that with known vulnerabilities or outdated versions can weaken the overall security of the application, potentially enabling various types of attacks."],
        
        ["A07 - Identification and Authentication Failures", 
         "Identification and authentication failures can occur when functions related to a user's identity, authentication, or session management are not implemented correctly or not adequately protected by an application. Attackers may be able to exploit identification and authentication failures by compromising passwords, keys, session tokens, or exploit other flaws to assume other users' identities."],
        
        ["A08 - Software and Data Integrity Failures", 
         "Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This can occur when you use software from untrusted sources and repositories or even software that has been tampered with at the source, in transit, or even the endpoint cache. Attackers can exploit this to potentially introduce unauthorized access, malicious code, or system compromise."],
        
        ["A09 - Security Logging and Monitoring Failures", 
         "Inadequate logging, monitoring, or reporting of security events, like login attempts, hinders the detection of suspicious activities and substantially increases the chances of an attacker successfully exploiting your application."],
        
        ["A10 - Server-Side Request Forgery", 
         "Server-Side Request Forgery (SSRF) is a type of server-side attack that results in the unauthorized exposure of sensitive information from the backend server of an application. In SSRF, the attacker sends malicious requests to an Internet-facing webserver, which then forwards these requests to a backend server located on the internal network, all on behalf of the attacker."]
    ]

    # Convert descriptions to Paragraphs for wrapping
    formatted_owasp_data = []
    # Header row
    formatted_owasp_data.append([
        Paragraph("<b>Name</b>", styles["Normal"]),
        Paragraph("<b>Description</b>", styles["Normal"])
    ])
    
    # Data rows
    for row in owasp_data[1:]:
        formatted_owasp_data.append([
            Paragraph(row[0], styles["Body"]),
            Paragraph(row[1], styles["Body"])
        ])

    owasp_table = Table(formatted_owasp_data, colWidths=[150, 350])
    owasp_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1976d2")), # Header Blue
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('PADDING', (0,0), (-1,-1), 6),
    ]))
    
    story.append(owasp_table)
    story.append(Spacer(1, 20))
    story.append(PageBreak())

    # ================= APPENDIX B =================
    addPara("6. APPENDIX B", styles["H1"], level=0)
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Risk calculation</b>", styles["H2"]))
    story.append(Spacer(1, 10))

    severity_definitions = [
        ["Severity", "CVSS Score", "Description"],
        ["Critical", "9.0-10.0", "Critical severity findings relate to an issue that can result in severe damage if not addressed immediately by the business."],
        ["High", "7.0-8.9", "High severity findings relate to an issue that requires prompt attention and high priority by the business."],
        ["Medium", "4.0-6.9", "Medium severity finding relates to an issue that has the potential to present a serious risk to the business."],
        ["Low", "0.1-3.9", "Low severity findings contradict security best practices and have minimal impact on the project or business."],
        ["Informational", "0.0", "Informational findings relate primarily to noncompliance with security best practices or are considered a security feature that would increase the security stance."]
    ]

    formatted_severity_data = []
    # Header
    formatted_severity_data.append([
        Paragraph("<b>Severity</b>", styles["Normal"]),
        Paragraph("<b>CVSS Score</b>", styles["Normal"]),
        Paragraph("<b>Description</b>", styles["Normal"])
    ])

    # Data Rows
    for row in severity_definitions[1:]:
        formatted_severity_data.append([
            Paragraph(f"<b>{row[0]}</b>", styles["Body"]), # Bold Severity Name
            Paragraph(row[1], styles["Body"]),
            Paragraph(row[2], styles["Body"])
        ])

    severity_table = Table(formatted_severity_data, colWidths=[100, 80, 320])
    
    # Base Style
    table_style = [
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#0070c0")), # Header Blue
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 0.5, colors.white), # White grid like image
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('PADDING', (0,0), (-1,-1), 10),
        
        # Row 1 (Critical) - Dark Red
        ('BACKGROUND', (0,1), (0,1), colors.HexColor("#bf0000")), 
        ('TEXTCOLOR', (0,1), (0,1), colors.white),
        ('BACKGROUND', (1,1), (-1,1), colors.HexColor("#f2f2f2")), # Light Grey for rest
        
        # Row 2 (High) - Red
        ('BACKGROUND', (0,2), (0,2), colors.HexColor("#ff0000")), 
        ('TEXTCOLOR', (0,2), (0,2), colors.white),
        ('BACKGROUND', (1,2), (-1,2), colors.white),
        
        # Row 3 (Medium) - Yellow/Gold
        ('BACKGROUND', (0,3), (0,3), colors.HexColor("#ffc000")),
        ('TEXTCOLOR', (0,3), (0,3), colors.white),
        ('BACKGROUND', (1,3), (-1,3), colors.HexColor("#f2f2f2")),
        
        # Row 4 (Low) - Green
        ('BACKGROUND', (0,4), (0,4), colors.HexColor("#00b050")),
        ('TEXTCOLOR', (0,4), (0,4), colors.white),
        ('BACKGROUND', (1,4), (-1,4), colors.white),
        
        # Row 5 (Informational) - Blue
        ('BACKGROUND', (0,5), (0,5), colors.HexColor("#00b0f0")),
        ('TEXTCOLOR', (0,5), (0,5), colors.white),
        ('BACKGROUND', (1,5), (-1,5), colors.HexColor("#f2f2f2")),
    ]
    
    severity_table.setStyle(TableStyle(table_style))
    story.append(severity_table)
    story.append(Spacer(1, 20))
    story.append(PageBreak())



    # ================= CONCLUSION =================
    addPara("7. Conclusion", styles["H1"], level=0)
    story.append(Spacer(1, 10))
    CONCLUSION_TEXT = """The security assessment of the target application has identified several vulnerabilities ranging across various severity levels. The presence of these findings indicates that while security controls are in place, there are critical areas where the application's security posture can be significantly strengthened.
<br/><br/>
Immediate attention should be directed toward remediating the 'Critical' and 'High' severity findings identified in this report. These vulnerabilities represent the most direct paths for potential exploitation and could lead to unauthorized access, data breaches, or service disruptions.
<br/><br/>
In addition to technical remediation, it is recommended that the organization adopts a continuous security monitoring and assessment lifecycle. Regular vulnerability scanning, combined with periodic deep-dive manual penetration testing, will ensure that new threats are identified and mitigated before they can be exploited.
<br/><br/>
All remediation efforts should be followed by a formal validation and re-testing phase to confirm that the implemented fixes effectively address the root causes of the vulnerabilities without introducing side effects. Protecting sensitive data and maintaining user trust remains a paramount objective for the long-term success of the application."""
    story.append(Paragraph(CONCLUSION_TEXT, styles["Body"]))
    story.append(Spacer(1, 20))

    doc.multiBuild(story, onLaterPages=footer)
    buffer.seek(0)

    return buffer
