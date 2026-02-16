---
id: "{{agent_id}}"
name: "{{agent_name}}"
version: "{{version}}"
tier: "{{tier}}"
tags: []
placeholders:
  - name: "objective"
    description: "O objetivo principal da tarefa"
    required: true
---

# System
{{system_prompt}}

# Developer
{{developer_instructions}}

# User Template
{{user_template}}
