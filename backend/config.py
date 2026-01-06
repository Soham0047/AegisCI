from pydantic import BaseModel


class Settings(BaseModel):
    sqlite_path: str = "backend/data/app.db"


settings = Settings()
