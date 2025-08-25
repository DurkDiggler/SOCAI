from soc_agent.config import Settings
import json
print(json.dumps(Settings.model_json_schema(), indent=2))
