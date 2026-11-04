#!/usr/bin/env bash
# OASIS demo launcher: clean state + all five components on one tiled screen.
cd "$(dirname "$0")/.." || exit 1
S=oasis
U="$(id -un)"
mkdir -p data
sudo -v || exit 1
sudo tmux kill-session -t $S 2>/dev/null
# clean state: clear firewall blocks, archive the old database
sudo nft flush set inet oasis blocklist 2>/dev/null
[ -f data/oasis.db ] && mv data/oasis.db "data/old_oasis_$(date +%Y%m%d_%H%M%S).db"
sudo touch data/windows.jsonl data/alerts.jsonl
sudo tmux new-session -d -x 220 -y 60 -s $S -n demo ".venv/bin/python src/sensor.py"
add() { sudo tmux split-window -t $S:demo "$1" && sudo tmux select-layout -t $S:demo tiled; }
add ".venv/bin/python src/detector.py"
add ".venv/bin/python src/responder.py --enforce"
sleep 3
sudo chown -R "$U":"$U" data
add "sudo -u $U .venv/bin/python src/explainer.py --watch"
add "sudo -u $U .venv/bin/python src/specialist.py --watch"
sudo tmux set-option -w -t $S:demo pane-border-status top
sudo tmux select-pane -t $S:demo.0 -T "1 SENSOR (trafik ozeti)"
sudo tmux select-pane -t $S:demo.1 -T "2 DETECTOR (kural tespiti)"
sudo tmux select-pane -t $S:demo.2 -T "3 RESPONDER (karar + engel)"
sudo tmux select-pane -t $S:demo.3 -T "4 EXPLAINER (LLM aciklamasi)"
sudo tmux select-pane -t $S:demo.4 -T "5 UZMAN AGENT (tur bazli ikinci gorus)"
sudo tmux attach -t $S
