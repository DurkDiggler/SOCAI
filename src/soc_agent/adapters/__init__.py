diff --git a//dev/null b/src/soc_agent/adapters/__init__.py
index 0000000000000000000000000000000000000000..478136dc30683cbc2d40f299041e5da118fd0f19 100644
--- a//dev/null
+++ b/src/soc_agent/adapters/__init__.py
@@ -0,0 +1,22 @@
+"""Vendor specific payload normalization utilities."""
+
+from .wazuh import normalize_wazuh_event
+from .crowdstrike import normalize_crowdstrike_event
+
+
+def normalize_event(event):
+    """Detect the vendor of ``event`` and normalise it accordingly.
+
+    If the event does not look like a known vendor payload it is returned
+    unchanged.  This keeps the adapter layer thin while allowing the rest of
+    the application to work with a consistent schema.
+    """
+
+    if "rule" in event and "agent" in event:
+        return normalize_wazuh_event(event)
+    if "eventType" in event or "Name" in event:
+        return normalize_crowdstrike_event(event)
+    return event
+
+
+__all__ = ["normalize_wazuh_event", "normalize_crowdstrike_event", "normalize_event"]
