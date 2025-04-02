import uuid
from contextvars import ContextVar

from fastapi import Request

request_id_context: ContextVar[str] = ContextVar("request_id", default=None)


async def add_request_id_middleware(request: Request, call_next):
    # Generate a unique request ID
    request_id = str(uuid.uuid4())
    # Set the request ID in the context variable
    request_id_context.set(request_id)
    # Add the request ID to the response headers
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response
