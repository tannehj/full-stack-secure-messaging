from pydantic import BaseModel, Field

class Student(BaseModel):
    id: int = Field(..., description="Unique student identifier")
    name: str = Field(..., description="Student's full name")
    gpa: float = Field(..., ge=0.0, le=4.0, description="GPA between 0.0 and 4.0")
