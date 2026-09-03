from pydantic import BaseModel


class DashboardStats(BaseModel):
    """
    Every field here is computed from a real database query in
    app/api/routes/dashboard.py -- there are no hardcoded numbers.
    detection_rate and avg_detection_time_seconds are 0/None until the
    detection engine (next phase) starts producing alerts to measure.
    """
    total_events: int
    events_today: int
    active_alerts: int
    critical_alerts: int
    high_alerts: int
    monitored_endpoints: int
    online_endpoints: int
    detection_rate: float | None
    avg_detection_time_seconds: float | None
    # Automated containment decisions recorded by app/soar/engine.py.
    # Recorded, not executed -- see that module's docstring; the console
    # labels the card accordingly rather than implying hosts were touched.
    soar_actions: int
    soar_actions_today: int
