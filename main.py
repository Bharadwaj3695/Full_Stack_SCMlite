from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from backend import users, shipments, Device  # match file names/case
from pymongo import MongoClient
from dotenv import load_dotenv
import os
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]


app = FastAPI()
app.include_router(users.router)
app.include_router(shipments.router)
app.include_router(Device.router)

# (optional) when you visit http://127.0.0.1:8000/ it will open users.html
@app.get("/")
async def root():
    return RedirectResponse(url="/frontend/users.html")
