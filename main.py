import os
import tempfile
from typing import Any, List

import duckdb
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import re

# Where to store the DuckDB database file
DB_DIR = "data"
DB_PATH = os.path.join(DB_DIR, "db.duckdb")
os.makedirs(DB_DIR, exist_ok=True)

app = FastAPI(
    title="Artemis Assignment – CSV SQL tool",
    description="Upload a CSV and query it as a table named 'tablename'.",
    version="1.0.0",
)

# Allow React dev server to talk to this backend.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "https://csv-sql-tool.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



def get_connection() -> duckdb.DuckDBPyConnection:
    """
    Return a connection to DuckDB (creates the file if it does not exist).
    """
    return duckdb.connect(DB_PATH)


class QueryRequest(BaseModel):
    sql: str


class QueryResponse(BaseModel):
    columns: List[str]
    rows: List[List[Any]]


@app.get("/")
def root():
    return {
        "message": "Backend is running. Use /api/upload to upload a CSV and /api/query to run SQL."
    }


@app.post("/api/upload")
async def upload_csv(file: UploadFile = File(...)):
    """
    Accept a CSV file, store it temporarily on disk,
    load it into a DuckDB table named 'tablename',
    and return how many rows were loaded.
    """
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only .csv files are supported.")

    # Save the uploaded file to a temporary file in chunks
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
            temp_path = tmp.name
            while True:
                chunk = await file.read(1024 * 1024)  # 1MB at a time
                if not chunk:
                    break
                tmp.write(chunk)
    finally:
        await file.close()

    # Load the CSV into the 'tablename' table
    try:
        conn = get_connection()
        conn.execute("DROP TABLE IF EXISTS tablename")

        conn.execute(
            """
            CREATE TABLE tablename AS
            SELECT * FROM read_csv_auto(?, header=True)
            """,
            [temp_path],
        )

        rows_loaded = conn.execute("SELECT COUNT(*) FROM tablename").fetchone()[0]

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load CSV: {e}")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

    return {"status": "ok", "rows_loaded": rows_loaded}


def _wrap_query_with_limit(sql: str, max_rows: int = 1000) -> str:
    """
    If this is a SELECT query, add a LIMIT (if not already present)
    to avoid returning too many rows.
    For non-SELECT statements (INSERT/UPDATE/DELETE), return as-is.
    """
    cleaned = sql.strip().rstrip(";")
    lower_sql = cleaned.lower().lstrip()

    # Only apply LIMIT logic to SELECT statements
    if not lower_sql.startswith("select"):
        return cleaned

    # If there's already a LIMIT, leave it as is
    if re.search(r"\blimit\b", lower_sql):
        return cleaned

    # Wrap the query and apply a LIMIT
    return f"SELECT * FROM ({cleaned}) AS subquery LIMIT {max_rows}"


# ---------- SECURITY: SQL validation before execution ----------

FORBIDDEN_PATTERNS = [
    r"\bread_csv_auto\b",
    r"\bread_parquet\b",
    r"\bparquet_scan\b",
    r"\bhttpfs\b",
    r"\bcopy\b",
    r"\battach\b",
    r"\bdetach\b",
    r"\bpragma\b",
    r"\binstall\b",
    r"\bload\b",
    r"\bexport\b",
    r"\bimport\b",
    r"\bcreate\s+table\b",
    r"\bdrop\s+table\b",
    r"\balter\b",
    r"\btruncate\b",
    r"\bcall\b",
    r"\bsystem\b",
]


def _validate_sql(sql: str) -> str:
    """
    Validate the incoming SQL:
    - Only a single statement (no multiple statements separated by ';')
    - Only allow: SELECT, INSERT, UPDATE, DELETE
    - Forbid dangerous functions/commands (file access, DDL, system operations)
    - Only allow operations on the 'tablename' table
    Returns the cleaned SQL without a trailing semicolon.
    """
    if not sql or not sql.strip():
        raise HTTPException(status_code=400, detail="SQL query cannot be empty.")

    stripped = sql.strip()
    if stripped.endswith(";"):
        stripped = stripped[:-1]

    lower_sql = stripped.lower()

    # Disallow multiple statements
    if ";" in lower_sql:
        raise HTTPException(
            status_code=400,
            detail="Multiple SQL statements are not allowed. Please run one statement at a time.",
        )

    # Only allow SELECT / INSERT / UPDATE / DELETE at the beginning
    allowed_verbs = ("select", "insert", "update", "delete")
    if not lower_sql.lstrip().startswith(allowed_verbs):
        raise HTTPException(
            status_code=400,
            detail="Only SELECT, INSERT, UPDATE and DELETE statements are allowed.",
        )

    # Block obvious file system access patterns
    if "/etc/" in lower_sql or ".." in lower_sql:
        raise HTTPException(
            status_code=400,
            detail="File system access is not allowed.",
        )

    # Forbid dangerous DuckDB functions/commands
    for pattern in FORBIDDEN_PATTERNS:
        if re.search(pattern, lower_sql):
            raise HTTPException(
                status_code=400,
                detail="This query uses a disallowed command or function.",
            )

    # Disallow JOINs entirely (only a single CSV-backed table is allowed)
    if re.search(r"\bjoin\b", lower_sql):
        raise HTTPException(
            status_code=400,
            detail="JOIN is not allowed. You can only work with the 'tablename' table.",
        )

    # If there's a FROM clause, enforce that it references 'tablename'
    if re.search(r"\bfrom\b", lower_sql):
        if not re.search(r"\bfrom\s+tablename\b", lower_sql):
            raise HTTPException(
                status_code=400,
                detail="You can only access the 'tablename' table loaded from your CSV.",
            )

    # UPDATE tablename ...
    if lower_sql.startswith("update ") and not re.match(r"update\s+tablename\b", lower_sql):
        raise HTTPException(
            status_code=400,
            detail="You can only UPDATE the 'tablename' table.",
        )

    # DELETE FROM tablename ...
    if lower_sql.startswith("delete ") and not re.match(r"delete\s+from\s+tablename\b", lower_sql):
        raise HTTPException(
            status_code=400,
            detail="You can only DELETE from the 'tablename' table.",
        )

    # INSERT INTO tablename ...
    if lower_sql.startswith("insert ") and not re.match(r"insert\s+into\s+tablename\b", lower_sql):
        raise HTTPException(
            status_code=400,
            detail="You can only INSERT into the 'tablename' table.",
        )

    return stripped


@app.post("/api/query", response_model=QueryResponse)
def run_query(body: QueryRequest):
    """
    Execute a SQL statement against the 'tablename' table and return columns + rows.
    Allows SELECT / INSERT / UPDATE / DELETE, restricted to the 'tablename' table.
    """
    # 1. Validate SQL (command type, dangerous functions, allowed table)
    safe_sql = _validate_sql(body.sql)

    # 2. If it's a SELECT, add LIMIT if needed
    final_sql = _wrap_query_with_limit(safe_sql)

    try:
        conn = get_connection()
        result = conn.execute(final_sql)

        # UPDATE/DELETE/INSERT do not necessarily return a result set
        if result.description is None:
            columns = []
            rows = []
        else:
            columns = [d[0] for d in result.description]
            rows = result.fetchall()
    except HTTPException:
        # Re-raise HTTPException from validation or other checks
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Query failed: {e}")

    return QueryResponse(columns=columns, rows=rows)
