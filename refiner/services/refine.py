import vana

from refiner.middleware.log_request_id_handler import request_id_context
from refiner.models.models import RefinementRequest, RefinementResponse


def refine(
        client: vana.Client,
        request: RefinementRequest,
        request_id: str = None
) -> RefinementResponse:
    # Set request ID in context if provided
    if request_id:
        request_id_context.set(request_id)

    vana.logging.info(f"Refining request: {request}")

    return RefinementResponse(
        add_refinement_tx_hash="0x123"
    )
