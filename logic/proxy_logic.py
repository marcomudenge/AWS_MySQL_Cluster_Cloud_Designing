from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import pymysql
import random
import os
import subprocess

app = FastAPI()

# Environment-based configuration
DB_USER = os.getenv("MYSQL_USER", "root")
DB_PASSWORD = os.getenv("MYSQL_PASSWORD", "password")
DB_NAME = "sakila"
MYSQL_PORT = 3306

MASTER_DB_HOST = os.getenv("MASTER_IP", "localhost")
WORKER1_DB_HOST = os.getenv("SLAVE_1_IP", "localhost")
WORKER2_DB_HOST = os.getenv("SLAVE_2_IP", "localhost")

PROXY_PORT = int(os.getenv("PORT", 8000))

# Define database nodes
DB_NODES = {
    "master": MASTER_DB_HOST,
    "worker1": WORKER1_DB_HOST,
    "worker2": WORKER2_DB_HOST,
}

def create_db_connection(host):
    """
    Establish a connection to a MySQL database.
    
    Args:
        host (str): The IP address or hostname of the database server.
        
    Returns:
        pymysql.connections.Connection: Active database connection.
    """
    return pymysql.connect(
            host=host,
            port=MYSQL_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
        )


def is_modification_query(query):
    """
    Checks if the query is a write operation.

    Args:
        query (str): The SQL query to analyze.

    Returns:
        bool: True if the query modifies the database, otherwise False.
    """
    write_operations = {"INSERT", "UPDATE", "DELETE", "CREATE", "ALTER", "DROP"}
    return query.strip().upper().split()[0] in write_operations

def measure_ping_latency(host):
    """
    Measure the response time of a node via ping.

    Args:
        host (str): The IP or hostname to ping.

    Returns:
        float: Response time in milliseconds, or infinity if the ping fails.
    """
    try:
        result = subprocess.run(
            ["ping", "-c", "1", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        ping = next(
            line for line in result.stdout.split("\n") if "time=" in line
        )

        latency = float(ping.split("time=")[1].split()[0])

        return latency
    
    except (subprocess.SubprocessError, StopIteration):
        return float("inf")

class QueryPayload(BaseModel):
    query: str
    implementation: int

@app.post('/query')
def process_query(payload: QueryPayload):
    """
    Handle incoming SQL queries by routing them to the appropriate database node.

    Args:
        request (QueryModel): Includes the SQL query and implementation type.

    Returns:
        dict: Result of the query execution, including the target node.
    """
    query = payload.query
    implementation = payload.implementation

    if not query or not implementation:
        return HTTPException(status_code=400, detail="No query provided")

    if is_modification_query(query):
        target_node = "master"
    else:
        if implementation == 1:
            target_node = "master"
        elif implementation == 2:
            target_node = random.choice(["worker1", "worker2"])
        else:
            latencies = [{"node": node, "latency": measure_ping_latency(DB_NODES[node])} for node in DB_NODES            ]
            target_node = min(latencies, key=lambda x: x["latency"])["node"]

    try:
        connection = create_db_connection(DB_NODES[target_node])

        with connection.cursor() as cursor:

            cursor.execute(query)

            if is_modification_query(query):

                return {
                    "status": "success",
                    "target_node": target_node,
                    "data": cursor.fetchall(),
                }

            else:

                connection.commit()
                return {
                    "status": "success",
                    "target_node": target_node
                }

    except Exception as error:
        raise HTTPException(status_code=500, detail=f"Query execution error: {error}")
    finally:
        connection.close()

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PROXY_PORT)
