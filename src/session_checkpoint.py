
import json
import os
import time


class SessionCheckpointStore:
    def __init__(self, sessions_dir="analysis_sessions"):
        self.sessions_dir = sessions_dir

    def _path(self, session_id: str, job_name: str) -> str:
        job_dir = os.path.join(self.sessions_dir, session_id, "jobs")
        os.makedirs(job_dir, exist_ok=True)
        return os.path.join(job_dir, f"{job_name}.json")

    def load(self, session_id: str, job_name: str) -> dict:
        path = self._path(session_id, job_name)
        if not os.path.exists(path):
            return {
                "completed_addresses": [],
                "failed_addresses": [],
            }

        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save(self, session_id: str, job_name: str, data: dict) -> None:
        path = self._path(session_id, job_name)
        data["last_updated"] = time.time()

        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        os.replace(tmp_path, path)