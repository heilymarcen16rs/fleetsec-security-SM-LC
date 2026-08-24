#!/usr/bin/env python3
"""Render a Markdown file to a styled PDF (WeasyPrint). Usage: md_to_pdf.py in.md out.pdf [Title]"""
import sys, markdown
from weasyprint import HTML

CSS = """
@page { size: A4; margin: 1.8cm 1.6cm; @bottom-right { content: "Página " counter(page) " / " counter(pages); font-size: 8pt; color: #667; } @bottom-left { content: "FleetSec — Confidencial"; font-size: 8pt; color: #667; } }
* { box-sizing: border-box; }
body { font-family: 'Helvetica Neue', Arial, sans-serif; font-size: 10.2pt; line-height: 1.45; color: #1f2933; }
h1 { font-size: 20pt; color: #0b3d5c; border-bottom: 3px solid #0b3d5c; padding-bottom: 6px; margin-top: 0; }
h2 { font-size: 14pt; color: #0b5394; border-bottom: 1px solid #cdd7e0; padding-bottom: 3px; margin-top: 20px; }
h3 { font-size: 11.5pt; color: #073763; margin-top: 16px; background: #eef3f8; padding: 4px 8px; border-left: 4px solid #0b5394; }
p, li { margin: 4px 0; }
code { font-family: 'DejaVu Sans Mono', Consolas, monospace; font-size: 8.6pt; background: #f3f4f6; padding: 1px 4px; border-radius: 3px; color: #b02a37; }
pre { background: #0f1b2d; color: #e6edf3; padding: 10px 12px; border-radius: 6px; font-size: 8.2pt; line-height: 1.35; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
pre code { background: none; color: #e6edf3; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 10px 0; font-size: 8.8pt; }
th { background: #0b3d5c; color: #fff; text-align: left; padding: 5px 7px; }
td { border: 1px solid #d0d7de; padding: 4px 7px; vertical-align: top; }
tr:nth-child(even) td { background: #f6f8fa; }
blockquote { border-left: 4px solid #f0ad4e; background: #fff8ec; margin: 8px 0; padding: 6px 12px; color: #614a1f; font-size: 9.4pt; }
strong { color: #0b3d5c; }
hr { border: none; border-top: 1px solid #cdd7e0; margin: 16px 0; }
"""

def main():
    src, out = sys.argv[1], sys.argv[2]
    md = open(src, encoding="utf-8").read()
    html_body = markdown.markdown(md, extensions=["tables", "fenced_code", "toc", "sane_lists"])
    html = f"<html><head><meta charset='utf-8'></head><body>{html_body}</body></html>"
    HTML(string=html).write_pdf(out, stylesheets=[__import__("weasyprint").CSS(string=CSS)])
    print("wrote", out)

if __name__ == "__main__":
    main()
