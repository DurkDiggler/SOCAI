from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

class EventIn(BaseModel):
    source: Optional[str] = None
    event_type: Optional[str] = Field(default=None, description="Canonical event type")
    severity: int = 0
    timestamp: Optional[str] = None
    message: Optional[str] = None
    ip: Optional[str] = None
    username: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

    model_config = {
        "extra": "allow"
    }
