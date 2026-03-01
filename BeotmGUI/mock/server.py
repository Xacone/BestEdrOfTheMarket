from datetime import datetime
from datetime import timedelta
import json
import random

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn


def load_data() -> list[dict]:
    f = open("example-50-events.json")
    data = json.load(f)
    f.close()
    return data


data = load_data()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"http://localhost:\d+",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def randomize_date(detection: dict) -> dict:
    new_date = (
        datetime(2024, 1, 1)
        + timedelta(
            seconds=random.randint(
                0,
                int(
                    (
                        datetime(2026, 12, 31, 23, 59, 59) - datetime(2024, 1, 1)
                    ).total_seconds()
                ),
            )
        )
    ).strftime("%Y-%m-%d %H:%M:%S")
    detection["DateAndTime"] = new_date
    return detection


@app.get("/all")
def get_all():
    return data


@app.get("/events")
def get_events():
    random_selection = random.sample(data, random.randint(5, 7))
    return [randomize_date(detection) for detection in random_selection]


if __name__ == "__main__":
    uvicorn.run("server:app", port=8000, reload=True)
