import os
import re
from pathlib import Path

agents_dir = Path(__file__).resolve().parent.parent / "agents"
output = []

def parse_frontmatter(content):
    match = re.search(r"^---\s+(.*?)\s+---", content, re.DOTALL)
    if match:
        fm = match.group(1)
        data = {}
        for line in fm.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                data[key.strip()] = value.strip()
        return data
    return {}

print("# 🤖 Atlas Agency - Diretório de Agentes\n")
print("Documentação oficial dos agentes disponíveis no sistema Codex/Arqos.\n")
print("| Agente | Descrição | Utilização |")
print("|---|---|---|")

for filename in os.listdir(agents_dir):
    if filename.endswith(".md") and filename != "README.md":
        filepath = os.path.join(agents_dir, filename)
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            data = parse_frontmatter(content)

            name = data.get('name', filename.replace('.md', ''))
            desc = data.get('description', 'Sem descrição.')

            # Simple translation map for descriptions if needed, but assuming English in file
            # Actually, I will let the user read the English description or translate it myself in the final step?
            # The user asked for "descrição individual de cada um e sua utilização".
            # The description in frontmatter usually contains usage info.

            print(f"| `{name}` | {desc} |")
