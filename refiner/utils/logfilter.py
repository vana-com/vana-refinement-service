from vana.logging import _logging

from refiner.middleware.log_request_id_handler import request_id_context


class RequestIdFilter(_logging.Filter):
    def filter(self, record: _logging.LogRecord) -> bool:
        # Get the current request ID from the context variable
        request_id = request_id_context.get()
        # Add the request ID to the log record (or use a default if not set)
        record.request_id = request_id if request_id else "N/A"
        return True
