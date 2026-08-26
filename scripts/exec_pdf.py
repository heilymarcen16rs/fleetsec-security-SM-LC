#!/usr/bin/env python3
"""
Executive PDF generator for FleetSec deliverables.
Cover + Table of Contents + confidential footer + corporate-blue theme + risk color coding.
Usage: exec_pdf.py <in.md> <out.pdf> "<Title>" "<Subtitle>"
"""
import sys, os, re, datetime, markdown
from weasyprint import HTML, CSS

AUTHOR = "Lady Marcela Romero Rivero"
ROLE = "Ingeniero de Ciberseguridad"
CLIENT = "Simon Movilidad"
CONF = "CONFIDENCIAL — Exclusivo para Simon Movilidad"
MONTHS = ["", "enero","febrero","marzo","abril","mayo","junio","julio",
          "agosto","septiembre","octubre","noviembre","diciembre"]

CSS_TMPL = """
@page {
  size: A4; margin: 2.0cm 1.7cm 1.9cm 1.7cm;
  @bottom-left  { content: "%(conf)s"; font-size: 7.5pt; color: #6b7a88; }
  @bottom-right { content: "Página " counter(page) " de " counter(pages); font-size: 7.5pt; color: #6b7a88; }
  @top-right    { content: "%(client)s"; font-size: 7.5pt; color: #9aa7b2; }
}
@page cover { margin: 0; @bottom-left { content: none; } @bottom-right { content: none; } @top-right { content: none; } }
* { box-sizing: border-box; }
body { font-family: 'DejaVu Sans', Arial, Helvetica, sans-serif; font-size: 10pt; line-height: 1.5; color: #14202b; }

/* ---------- Cover ---------- */
.cover { page: cover; height: 100%%; page-break-after: always; position: relative; }
.cover .band { background: linear-gradient(135deg,#0B3D5C 0%%,#12507a 60%%,#1E63A6 100%%); color:#fff;
  padding: 3.2cm 1.9cm 2.2cm 1.9cm; }
.cover .kicker { font-size: 10pt; letter-spacing: .22em; text-transform: uppercase; color:#bcd6ea; margin-bottom: 10px; }
.cover h1.ct { font-size: 30pt; line-height: 1.12; margin: 0 0 10px 0; color:#fff; border:0; }
.cover .sub { font-size: 13pt; color:#dbe9f4; font-weight: 300; }
.cover .meta { padding: 1.6cm 1.9cm; }
.cover .meta table { width: 100%%; border-collapse: collapse; font-size: 10.5pt; }
.cover .meta td { padding: 7px 0; border-bottom: 1px solid #e4ebf1; vertical-align: top; }
.cover .meta td.k { color:#5b6b78; width: 34%%; text-transform: uppercase; letter-spacing:.05em; font-size: 8.5pt; }
.cover .meta td.v { color:#14202b; font-weight: 600; }
.cover .conf { position: absolute; bottom: 1.4cm; left: 1.9cm; right:1.9cm; font-size: 8.5pt; color:#b23b3b;
  border-top: 2px solid #C0392B; padding-top: 8px; font-weight: 700; letter-spacing:.03em; }

/* ---------- Table of contents ---------- */
.toc-wrap { page-break-after: always; }
.toc-wrap h2 { color:#0B3D5C; border-bottom: 2px solid #0B3D5C; padding-bottom:6px; }
.toc ul { list-style: none; padding-left: 0; }
.toc > ul > li { margin: 6px 0; font-weight: 700; color:#0B3D5C; }
.toc ul ul { padding-left: 16px; }
.toc ul ul li { font-weight: 400; color:#33454f; margin: 3px 0; }
.toc a { text-decoration: none; color: inherit; }

/* ---------- Headings ---------- */
h1 { font-size: 18pt; color:#0B3D5C; border-bottom: 3px solid #0B3D5C; padding-bottom: 6px; margin-top: 6px; }
h2 { font-size: 13.5pt; color:#12507a; border-bottom: 1px solid #cfdae3; padding-bottom: 3px; margin-top: 20px; }
h3 { font-size: 11pt; color:#0B3D5C; background:#eef4f9; border-left:4px solid #1E63A6; padding: 4px 8px; margin-top: 15px; }
p, li { margin: 4px 0; }
strong { color:#0B3D5C; }
a { color:#12507a; }

/* ---------- Code ---------- */
code { font-family:'DejaVu Sans Mono',Consolas,monospace; font-size:8.4pt; background:#eef2f5; padding:1px 4px; border-radius:3px; color:#a23; }
pre { background:#0f1b2d; color:#e6edf3; padding:9px 11px; border-radius:6px; font-size:8pt; line-height:1.35; white-space:pre-wrap; word-wrap:break-word; }
pre code { background:none; color:#e6edf3; padding:0; }

/* ---------- Tables ---------- */
table { border-collapse: collapse; width:100%%; margin: 9px 0; font-size: 8.7pt; }
th { background:#0B3D5C; color:#fff; text-align:left; padding:5px 7px; font-size:8.4pt; }
td { border:1px solid #d3dce3; padding:4px 7px; vertical-align: top; }
tr:nth-child(even) td { background:#f5f8fa; }

/* ---------- Risk color coding ---------- */
.sev { padding:1px 7px; border-radius:9px; font-weight:700; font-size:8pt; white-space:nowrap; }
.sev-crit { background:#fdecea; color:#C0392B; border:1px solid #C0392B; }
.sev-high { background:#fdf0e3; color:#C56A11; border:1px solid #E67E22; }
.sev-med  { background:#fef8e0; color:#9A7D0A; border:1px solid #D4AC0D; }
.sev-low  { background:#e9f7ef; color:#1E8449; border:1px solid #2ECC71; }

blockquote { border-left:4px solid #E67E22; background:#fff8ec; margin:8px 0; padding:6px 12px; color:#5c4a24; font-size:9pt; }
hr { border:0; border-top:1px solid #cfdae3; margin:16px 0; }
img { max-width:100%%; max-height:20cm; height:auto; display:block; margin:10px auto; }
"""

SEV = [
    (re.compile(r'\b(CR[IÍ]TICO|CRITICAL|Cr[ií]tico)\b'), 'sev sev-crit'),
    (re.compile(r'\b(ALTO|HIGH|Alto)\b'),                 'sev sev-high'),
    (re.compile(r'\b(MEDIO|MEDIUM|Medio)\b'),             'sev sev-med'),
    (re.compile(r'\b(BAJO|LOW|Bajo)\b'),                  'sev sev-low'),
]

def colorize_cells(html):
    def repl_td(m):
        inner = m.group(2)
        for rx, cls in SEV:
            inner = rx.sub(lambda x: f'<span class="{cls}">{x.group(0)}</span>', inner)
        return m.group(1) + inner + m.group(3)
    return re.sub(r'(<td[^>]*>)(.*?)(</td>)', repl_td, html, flags=re.S)

def build(md_path, out_path, title, subtitle):
    text = open(md_path, encoding='utf-8').read()
    # strip leading H1 (title lives on the cover)
    text = re.sub(r'^\s*#\s+.*\n', '', text, count=1)
    # (legacy) neutralize any leftover diagram code blocks
    text = re.sub(r'```mermaid.*?```',
                  '\n> **Diagrama** — imagen renderizada disponible en el repositorio.\n',
                  text, flags=re.S)
    md = markdown.Markdown(extensions=['tables','fenced_code','toc','sane_lists','attr_list'])
    body = md.convert(text)
    body = colorize_cells(body)
    toc = md.toc  # <div class="toc">...</div>
    today = datetime.date.today()
    fecha = f"{today.day} de {MONTHS[today.month]} de {today.year}"
    cover = f"""
    <section class="cover">
      <div class="band">
        <div class="kicker">Prueba Técnica · Ciberseguridad</div>
        <h1 class="ct">{title}</h1>
        <div class="sub">{subtitle}</div>
      </div>
      <div class="meta">
        <table>
          <tr><td class="k">Preparado por</td><td class="v">{AUTHOR}</td></tr>
          <tr><td class="k">Rol</td><td class="v">{ROLE}</td></tr>
          <tr><td class="k">Cliente</td><td class="v">{CLIENT}</td></tr>
          <tr><td class="k">Escenario</td><td class="v">FleetSec S.A.S. — Telemetría de flotas</td></tr>
          <tr><td class="k">Fecha</td><td class="v">{fecha}</td></tr>
          <tr><td class="k">Versión</td><td class="v">1.0</td></tr>
        </table>
      </div>
      <div class="conf">{CONF}</div>
    </section>
    <section class="toc-wrap"><h2>Tabla de contenido</h2>{toc}</section>
    """
    html = f"<html><head><meta charset='utf-8'></head><body>{cover}{body}</body></html>"
    css = CSS(string=CSS_TMPL % {"conf": CONF, "client": CLIENT})
    base = os.path.dirname(os.path.abspath(md_path))
    HTML(string=html, base_url=base).write_pdf(out_path, stylesheets=[css])
    print("wrote", out_path)

if __name__ == '__main__':
    build(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
