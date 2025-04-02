from pydantic import BaseModel, Field


class RefinementRequest(BaseModel):
    file_id: int = Field(..., description="File ID of the file in the Data Registry to be refined")
    encryption_key: str = Field(...,
                                description="Symmetric encryption key for the file so it can be decrypted and refined")
    refiner_id: str = Field(...,
                            description="Refiner ID in the Data Refiner Registry containing the instructions for refinement")


class RefinementResponse(BaseModel):
    add_refinement_tx_hash: str = Field(...,
                                        description="Transaction hash for the refinement being added to the Data Registry")
