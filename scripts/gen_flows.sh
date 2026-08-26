#!/usr/bin/env bash
# Renderiza pipeline e incidente a PNG con Graphviz.
set -e
cd "$(dirname "$0")/.."
dot -Tpng -Gdpi=150 scripts/pipeline.dot -o docs/diagrams/pipeline.png
dot -Tpng -Gdpi=150 scripts/incident.dot -o docs/diagrams/incident-timeline.png
echo "Diagramas regenerados en docs/diagrams/"
