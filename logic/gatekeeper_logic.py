import os
import requests

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from pydantic import BaseModel

app = FastAPI()

TRUSTED_IP = os.getenv('TRUSTED_IP')
TRUSTED_PORT = int(os.getenv('TRUSTED_PORT', 8000))
GATEKEEPER_PORT = int(os.getenv('GATEKEEPER_PORT', 8000))

class QueryPayload(BaseModel):
    query: str
    implementation: int

@app.post("/query")
def process_query(payload: QueryPayload):
    """
    Processes incoming requests and forwards them to a trusted host.

    Args:
        payload (QueryPayload): Contains the query string and implementation ID.

    Returns:
        JSONResponse: The response from the trusted host or an error message.
    """
    query = payload.query.strip()
    implementation = payload.implementation
    
    if not query or not implementation:
        raise HTTPException(status_code=400, detail="Query and implementation fields are required.")

    # Construct the trusted host URL
    trusted_instance_url = f"http://{TRUSTED_IP}:{TRUSTED_PORT}/query"

    try:
        response = requests.post(
            trusted_instance_url,
            json={"query": query, "implementation": implementation}
        )
        response.raise_for_status()
        return JSONResponse(content=response.json(), status_code=response.status_code)
    except requests.RequestException as err:
        raise HTTPException(status_code=502, detail=f"Failed to forward request: {err}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=GATEKEEPER_PORT)