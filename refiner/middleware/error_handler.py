import vana
from fastapi import Request
from fastapi.responses import JSONResponse

from refiner.errors.exceptions import RefinementServiceBaseException


async def error_handler_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except RefinementServiceBaseException as exc:
        vana.logging.error(f"Handled error: {exc.error_code} - {exc.detail}")
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.detail
        )
    except Exception as exc:
        # Log unexpected exceptions with full traceback
        vana.logging.error(f"Unhandled exception: {str(exc)}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "INTERNAL_SERVER_ERROR",
                    "message": "An unexpected error occurred",
                    "details": {
                        "type": exc.__class__.__name__,
                        "message": str(exc)
                    }
                }
            }
        )
