import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

# TODO: flesh out instruction with full output format
static_analysis_agent = LlmAgent(
    name="static_analysis_agent",
    model="gemini-2.5-flash",
    instruction="You are a malware analyst. Classify malware type and output JSON."
)

async def run_static_analysis(ingestion_output: dict):
    # TODO: implement
    pass
