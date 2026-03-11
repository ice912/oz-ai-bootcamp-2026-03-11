from openai import asyncOpenAI

from config import pydantic_settings

client = asyncOpenAI(api_key=settings.OPEN_API_KEY)