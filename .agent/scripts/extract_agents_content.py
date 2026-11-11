import os
import re
from pathlib import Path

agents_dir = Path(__file__).resolve().parent.parent / "agents"

def extract_info(content):
    name = "Desconhecido"
    description = "Sem descrição."
    usage = "Consulte o arquivo."

    # Extract Name (First H1)
    h1_match = re.search(r"^#\s+(.+)$", content, re.MULTILINE)
    if h1_match:
        name = h1_match.group(1).strip()

    # Extract Overview (Text after ## Overview)
    overview_match = re.search(r"##\s+Overview\s+(.*?)(?=\n#|\Z)", content, re.DOTALL | re.IGNORECASE)
    if overview_match:
        description = overview_match.group(1).strip().replace('\n', ' ')
        description = ' '.join(description.split()[:50]) + "..." # Truncate

    # Extract Usage (Look for "Usage" or "Identity" or "Mission")
    usage_match = re.search(r"##\s+(Usage|Mission|Role|Core Philosophy)\s+(.*?)(?=\n#|\Z)", content, re.DOTALL | re.IGNORECASE)
    if usage_match:
        usage = usage_match.group(2).strip().replace('\n', ' ')
        usage = ' '.join(usage.split()[:30]) + "..."

    return name, description, usage

print("# 🤖 Atlas Agency - Diretório de Agentes\n")
print("| Arquivo | Nome Detectado | Resumo |\n|---|---|---|")

for filename in sorted(os.listdir(agents_dir)):
    if filename.endswith(".md") and filename != "README.md":
        filepath = os.path.join(agents_dir, filename)
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
                name, desc, usage = extract_info(content)
                print(f"| `{filename}` | {name} | {desc} |")
        except Exception as e:
            print(f"| `{filename}` | Erro | {str(e)} |")
