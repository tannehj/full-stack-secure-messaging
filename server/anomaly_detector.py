import json

def is_anomalous(student_json: str) -> bool:
    """
    Simple anomaly detection for demonstration.
       AI/anomaly detection module.
    """

    # Convert to dict
    try:
        data = json.loads(student_json)
    except Exception:
        return True  # invalid JSON is anomalous

    name = data.get("name", "").lower()

    # Rule 1: SQL injection-like patterns
    sql_terms = ["drop table", "delete *", "insert into", "select * from"]
    if any(term in name for term in sql_terms):
        return True

    # Rule 2: Bad GPA values
    gpa = data.get("gpa", 0)
    if not (0.0 <= gpa <= 4.0):
        return True

    # Rule 3: Suspicious text in name
    if "hack" in name or "attack" in name:
        return True

    return False
