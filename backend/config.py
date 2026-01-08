from pydantic import BaseModel


class Settings(BaseModel):
    sqlite_path: str = "backend/data/app.db"
    jobs_db_path: str = "backend/data/jobs.db"
    gateway_events_db_path: str = "backend/data/gateway_events.db"
    config_db_path: str = "backend/data/config.db"


settings = Settings()
