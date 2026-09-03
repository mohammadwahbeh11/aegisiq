from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime

app = FastAPI(title="Lightweight SIEM & SOAR Backend", version="1.1.0")

# Enable CORS for frontend connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for logs, agents, and SOAR actions
logs_storage = [
    {
        "hostname": "ubuntu-server-01",
        "event_type": "SSH Brute Force Attempt",
        "source_ip": "192.168.1.105",
        "severity": "high",
        "mitre_technique": "T1110",
        "timestamp": datetime.utcnow().isoformat()
    }
]

agents_storage = [
    {"id": "001", "name": "ubuntu-server-01", "ip": "192.168.1.10", "os": "Ubuntu 22.04.4 LTS", "status": "active"},
    {"id": "002", "name": "wazuh-agent-02", "ip": "192.168.1.15", "os": "Ubuntu 22.04.4 LTS", "status": "active"}
]

# سجلات الاستجابة التلقائية (SOAR)
soar_actions_storage = [
    {
        "action_type": "IP Block (iptables DROP)",
        "target_ip": "192.168.1.50",
        "rule_triggered": "Unauthorized Privilege Escalation",
        "status": "Blocked Successfully",
        "timestamp": datetime.utcnow().isoformat()
    }
]

@app.get("/")
def read_root():
    return {"status": "SIEM & SOAR Backend is running successfully"}

@app.get("/api/logs")
def get_logs():
    return {"logs": logs_storage}

@app.post("/api/logs/ingest")
def ingest_log(payload: dict = Body(...)):
    if not payload.get("timestamp"):
        payload["timestamp"] = datetime.utcnow().isoformat()
    
    # التأكد من حفظ الـ mitre_technique القادمة من الجسر أو إعطاء N/A ديناميكية بدلاً من تثبيتها
    if not payload.get("mitre_technique"):
        payload["mitre_technique"] = "N/A"
    
    # إضافة السجل الجديد
    logs_storage.insert(0, payload)
    
    # محاكاة الاستجابة التلقائية (SOAR) في حال كان التنبيه Critical أو High
    severity = payload.get("severity", "").lower()
    if severity in ["critical", "high"]:
        source_ip = payload.get("source_ip", "127.0.0.1")
        event_type = payload.get("event_type", "Security Event")
        
        soar_action = {
            "action_type": "Automatic IP Isolation (iptables)",
            "target_ip": source_ip,
            "rule_triggered": event_type,
            "status": "Mitigated / Blocked",
            "timestamp": payload["timestamp"]
        }
        # منع التكرار وإضافة الإجراء الجديد للقائمة
        if not any(a["target_ip"] == source_ip for a in soar_actions_storage):
            soar_actions_storage.insert(0, soar_action)

    return {"status": "success", "message": "Log ingested and evaluated by SOAR"}

@app.get("/api/alerts")
def get_alerts():
    formatted_alerts = []
    for log in logs_storage:
        formatted_alerts.append({
            "severity": log.get("severity", "medium"),
            "rule_name": log.get("event_type", "Unknown Event"),
            # تم تعديلها لتأخذ القيمة الحقيقية ديناميكياً بدون فرض T1078 افتراضياً
            "mitre_technique": log.get("mitre_technique", "N/A"),
            "source_ip": log.get("source_ip", "127.0.0.1"),
            "timestamp": log.get("timestamp", datetime.utcnow().isoformat())
        })
    return formatted_alerts

@app.get("/api/agents")
def get_agents():
    return {
        "source": "wazuh-manager",
        "agents": agents_storage
    }

# --- مسار عرض إجراءات الاستجابة التلقائية SOAR ---
@app.get("/api/soar/actions")
def get_soar_actions():
    return {"actions": soar_actions_storage}