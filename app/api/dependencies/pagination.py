"""
Pagination dependencies
"""
from fastapi import Query


async def get_pagination(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records to return")
):
    """
    Pagination dependency

    Args:
        skip: Number of records to skip
        limit: Number of records to return

    Returns:
        Dictionary with skip and limit
    """
    return {"skip": skip, "limit": limit}
