from flask import Flask, request, render_template, send_file
import os
import json
from werkzeug.utils import secure_filename
from src.parser import parse_nessus
from src.log_parser import parse_apache_log
from src.filters import apply_rules, apply_context
from src.correlator import correlate
from src.ai_agent import multi_agent_consensus
from src.report_gen import generate_report

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REPORT_FOLDER'] = 'reports'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_files():
    if 'nessus_file' not in request.files or 'log_file' not in request.files:
        return "Both Nessus and Log files are required", 400
    
    nessus_file = request.files['nessus_file']
    log_file = request.files['log_file']
    
    if nessus_file.filename == '' or log_file.filename == '':
        return "No file selected", 400
    
    # Save files
    nessus_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(nessus_file.filename))
    log_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(log_file.filename))
    nessus_file.save(nessus_path)
    log_file.save(log_path)
    
    # --- PIPELINE EXECUTION ---
    print("[*] Parsing Nessus...")
    raw_vulns = parse_nessus(nessus_path)
    print(f"[+] Found {len(raw_vulns)} vulnerabilities.")
    
    print("[*] Parsing Logs...")
    logs = parse_apache_log(log_path)
    print(f"[+] Found {len(logs)} log entries.")
    
    print("[*] Applying Rules & Context...")
    step1 = apply_rules(raw_vulns)
    step2 = apply_context(step1)
    
    print("[*] Correlating & Running AI Consensus...")
    final_results = []
    for vuln in step2:
        evidence = correlate(vuln, logs)
        ai_decision = multi_agent_consensus(vuln, evidence)
        
        # Combine all data
        vuln.update(evidence)
        vuln.update(ai_decision)
        
        # Calculate priority score (0-10)
        priority = (vuln['cvss_score'] / 10) * 5 + (evidence['correlation_score'] / 10) * 3 + (ai_decision['confidence'] / 100) * 2
        vuln['priority_score'] = round(priority, 2)
        
        # Only keep if AI says True Positive or Needs Review
        if ai_decision['final_verdict'] in ['TRUE POSITIVE', 'NEEDS REVIEW']:
            final_results.append(vuln)
    
    # Sort by priority score
    final_results.sort(key=lambda x: x['priority_score'], reverse=True)
    
    print(f"[+] Final threats: {len(final_results)}")
    
    # Generate Report
    report_filename = f"report_{int(time.time())}.pdf"
    report_path = generate_report(final_results, report_filename)
    
    return send_file(report_path, as_attachment=True)

import time
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
