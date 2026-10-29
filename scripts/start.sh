#!/usr/bin/env bash
# Start OASIS (sensor, detector, responder) in one root tmux session.
# Usage: ./scripts/start.sh [--enforce]
cd "$(dirname "$0")/.." || exit 1
MODE="${1:-}"
S=oasis
mkdir -p data && touch data/windows.jsonl data/alerts.jsonl
sudo -v || exit 1   # password once; tmux itself runs as root
sudo tmux kill-session -t $S 2>/dev/null
sudo tmux new-session -d -s $S -n sensor ".venv/bin/python src/sensor.py"
sudo tmux new-window -t $S -n detector ".venv/bin/python src/detector.py"
sudo tmux new-window -t $S -n responder ".venv/bin/python src/responder.py $MODE"
sudo tmux attach -t $S
