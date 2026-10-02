#!/usr/bin/env bash
# Run the Matrix Advisor demo (ISE simulator + IPFIX generator) in a Lima VM on macOS.
#
#   brew install lima            # once
#   brew install ollama          # optional but recommended: the LLM runs natively (Metal GPU)
#   ./deploy/lima/lima-demo.sh
#
# The UI is then on http://localhost:8080 (Lima forwards the VM's TCP ports to the Mac).
set -euo pipefail

VM=${VM:-matrix-advisor}
REPO=${REPO:-https://github.com/rlienard/matrix-advisor.git}
MODEL=${MODEL:-qwen2.5:7b}

command -v limactl >/dev/null || { echo "Lima n'est pas installé : brew install lima"; exit 1; }

# 1. LLM on the Mac (much faster than CPU inference inside the VM)
if command -v ollama >/dev/null && curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
  echo "Ollama détecté sur le Mac, téléchargement de $MODEL si nécessaire…"
  ollama pull "$MODEL"
else
  echo "Ollama ne tourne pas sur le Mac : la démo fonctionnera avec l'analyse heuristique seule."
  echo "(Pour l'activer : brew install ollama && ollama serve, puis relancez ce script.)"
fi

# 2. VM with Docker (rootless) from Lima's docker template
if ! limactl list -q | grep -qx "$VM"; then
  limactl start --name="$VM" --cpus=4 --memory=8 --disk=40 --tty=false template://docker
elif [ "$(limactl list --format '{{.Status}}' "$VM")" != "Running" ]; then
  limactl start --tty=false "$VM"
fi

# 3. Clone or update the repo inside the VM and start the stack
limactl shell "$VM" bash -s -- "$REPO" <<'EOS'
set -euo pipefail
cd ~
[ -d matrix-advisor ] || git clone "$1" matrix-advisor
cd matrix-advisor
git pull --ff-only
export MA_CONFIG_TEMPLATE=/app/deploy/config.lima.yaml
docker compose -f docker-compose.yml -f deploy/lima/docker-compose.lima.yml --profile demo up -d --build
echo
echo "Mot de passe administrateur :"
for _ in $(seq 30); do
  docker compose exec -T matrix-advisor cat /data/initial-admin-password 2>/dev/null && break
  sleep 2
done
EOS

echo
echo "Interface : http://localhost:8080"
echo "Logs      : limactl shell $VM -- bash -c 'cd ~/matrix-advisor && docker compose logs -f matrix-advisor'"
echo "Arrêt     : limactl stop $VM"
