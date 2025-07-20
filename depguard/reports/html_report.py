# reports/html_report.py

from jinja2 import Template
from collections import Counter

def generate_combined_html_report(data, output_file='combined_report.html'):
    total     = sum(len(pkg['vulns']) for pkg in data)
    counts    = Counter(v['severity'] for pkg in data for v in pkg['vulns'])
    affected  = sum(1 for pkg in data if pkg['vulns'])

    template = Template("""
<html>
<head><title>Combined Dependency Scan Report</title>
<style>
  body { font-family: Arial, sans-serif; padding: 20px; }
  h1 { color: #333; }
  .summary, .package { margin-bottom: 30px; }
  .vuln { border-bottom: 1px solid #ccc; padding: 10px 0; }
  .metrics ul { margin: 0; padding-left: 20px; }
</style>
</head>
<body>
  <h1>Combined Dependency Scan Report</h1>
  <div class="summary">
    <h2>Summary</h2>
    <ul>
      <li>Total vulnerabilities: {{ total }}</li>
      <li>Affected packages: {{ affected }} of {{ data|length }}</li>
      {% for sev, cnt in counts.items() %}
        <li>{{ sev }}: {{ cnt }}</li>
      {% endfor %}
    </ul>
  </div>

  {% for pkg in data %}
    <div class="package">
      <h2>{{ pkg.name }}{% if pkg.version %}=={{ pkg.version }}{% endif %} (Risk Score: {{ pkg.risk_score }})</h2>
      {% if pkg.vulns %}
        {% for v in pkg.vulns %}
          <div class="vuln">
            <h3>{{ v.id }} &mdash; Score: {{ v.score }} ({{ v.severity }})</h3>
            <div class="metrics">
              <strong>CVSS v3 Metrics:</strong>
              <ul>
              {% for key, val in v.metrics.items() %}
                <li>{{ key }}: {{ val }}</li>
              {% endfor %}
              </ul>
            </div>
            <p>{{ v.details|safe }}</p>
          </div>
        {% endfor %}
      {% else %}
        <p>No vulnerabilities found.</p>
      {% endif %}
    </div>
  {% endfor %}
</body>
</html>
""")

    html = template.render(total=total, counts=counts, affected=affected, data=data)
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
