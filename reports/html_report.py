# depguard/reports/html_report.py

import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader

def generate_combined_html_report(
    results,
    output_path="HtmlAndSbom/combined_report.html",
    history_limit=20
):
    """
    Generate the combined HTML report of vulnerabilities.
    - If an existing report is found at output_path, move it into a History subfolder,
      renaming with a timestamp (YYYY-MM-DD_HH-MM-SS).
    - Keep only the most recent `history_limit` reports in History/.
    - Then render and write the new report (including a footer timestamp).
    """

    # 1) Ensure output directory exists
    output_dir = os.path.dirname(output_path)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    # 2) Archive old report if present
    history_dir = os.path.join(output_dir, "History")
    if os.path.exists(output_path):
        # create History/ if needed
        os.makedirs(history_dir, exist_ok=True)

        # build timestamped filename
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        basename = os.path.basename(output_path)                 # e.g. "combined_report.html"
        name, ext   = os.path.splitext(basename)                # ("combined_report", ".html")
        archived    = f"{name}_{timestamp}{ext}"                 # "combined_report_2025-07-27_14-30-00.html"
        archived_path = os.path.join(history_dir, archived)

        # move old report into History/
        os.rename(output_path, archived_path)

        # prune oldest files if exceeding history_limit
        entries = [
            fn for fn in os.listdir(history_dir)
            if os.path.isfile(os.path.join(history_dir, fn))
        ]
        # sort by modification time (oldest first)
        entries.sort(key=lambda fn: os.path.getmtime(os.path.join(history_dir, fn)))

        # delete oldest to enforce limit
        excess = len(entries) - history_limit
        if excess > 0:
            for old_fn in entries[:excess]:
                try:
                    os.remove(os.path.join(history_dir, old_fn))
                except OSError:
                    pass  # if deletion fails, skip

    # 3) Compute summary counts by severity
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for pkg in results:
        for v in pkg["vulns"]:
            score = v.get("score", 0)
            if score >= 9.0:
                counts["critical"] += 1
            elif score >= 7.0:
                counts["high"] += 1
            elif score >= 4.0:
                counts["medium"] += 1
            else:
                counts["low"] += 1

    total_issues = sum(counts.values())
    affected_packages = sum(1 for pkg in results if pkg["vulns"])

    # 4) Render with Jinja2 (passing `now` for the timestamp footer)
    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=True)
    template = env.get_template("report.html")

    rendered = template.render(
        results=results,
        counts=counts,
        total_issues=total_issues,
        affected_packages=affected_packages,
        now=datetime.now()
    )

    # 5) Write out the fresh report
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)

    return output_path
