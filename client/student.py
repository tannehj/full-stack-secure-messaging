import json

class Student:
    def __init__(self, id: int, name: str, gpa: float):
        self.id = id
        self.name = name
        self.gpa = gpa

    def to_json(self) -> str:
        """Return JSON string representation of student."""
        return json.dumps({
            "id": self.id,
            "name": self.name,
            "gpa": self.gpa
        })
