#!/usr/bin/env bash
# Start OASIS (sensor, detector, responder, explainer) in one tmux session.
# Usage: ./scripts/start.sh [--enforce]
cd "$(dirname "$0")/.." || exit 1
MODE="${1:-}"
S=oasis
U="$(id -un)"
mkdir -p data
sudo -v || exit 1   # password once; tmux itself runs as root
sudo touch data/windows.jsonl data/alerts.jsonl
sudo tmux kill-session -t $S 2>/dev/null
sudo tmux new-session -d -s $S -n sensor ".venv/bin/python src/sensor.py"
sudo tmux new-window -t $S -n detector ".venv/bin/python src/detector.py"
sudo tmux new-window -t $S -n responder ".venv/bin/python src/responder.py $MODE"
sleep 3
sudo chown -R "$U":"$U" data   # hand root-created files back to the user
# the explainer does not need root: run it as the normal user
sudo tmux new-window -t $S -n explainer "sudo -u $U .venv/bin/python src/explainer.py --watch"
sudo tmux attach -t $S
