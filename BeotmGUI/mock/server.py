import json
import random

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn


def load_data() -> list[dict]:
    f = open('example-50-events.json')
    data = json.load(f)
    f.close()
    return data

data = load_data()

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    # TODO: restrict to localhost ?
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/all")
def get_all():
    return data

@app.get("/events")
def get_events():
    random_selection = random.sample(data, random.randint(1,20))
    return random_selection


if __name__ == "__main__":
    uvicorn.run("server:app", port=8000, reload=True)