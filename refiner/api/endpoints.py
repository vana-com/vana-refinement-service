import vana
from fastapi import APIRouter

from refiner.models.models import RefinementRequest, RefinementResponse

refine_router = APIRouter(prefix="/refine", tags=["refine"])


@refine_router.post("/", response_model=RefinementResponse)
async def submit_refinement(
        refinement_request: RefinementRequest,
):
    """
    Submit a new refinement request.
    """

    vana.logging.info(f"Received refinement request: {refinement_request}")

    return RefinementResponse(
        add_refinement_tx_hash="0x1234567890abcdef"
    )


@refine_router.get("/health", tags=["health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}
