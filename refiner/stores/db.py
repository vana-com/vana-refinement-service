import os
import logging
from pathlib import Path
from contextlib import contextmanager
from typing import Generator, Callable

from sqlalchemy import create_engine, Column, String, Integer, Text, DateTime, Index, func, event, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import NullPool

logger = logging.getLogger(__name__)

# Create database directory if it doesn't exist
STORES_DB_DIR = Path(os.getenv('STORES_DB_DIR', "/app/data"))
STORES_DB_PATH = STORES_DB_DIR / "refinement_jobs.db"
os.makedirs(STORES_DB_DIR, exist_ok=True)

# SQLite connection string
SQLALCHEMY_DATABASE_URL = f"sqlite:///{STORES_DB_PATH}"

# Create SQLAlchemy engine with proper SQLite configuration
# For SQLite, use NullPool to avoid connection pooling issues and enable WAL mode for better concurrency
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    poolclass=NullPool,  # Use NullPool for SQLite instead of QueuePool
    echo=False,  # Set to True for SQL debugging
    connect_args={
        "check_same_thread": False,  # Allow multi-threading
        "timeout": 20,  # Connection timeout in seconds
    }
)

# Enable WAL mode for better concurrent access
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Set SQLite pragmas for better performance and concurrency"""
    cursor = dbapi_connection.cursor()
    # Enable WAL mode for better concurrent read/write access
    cursor.execute("PRAGMA journal_mode=WAL")
    # Set synchronous mode to FULL for better safety
    cursor.execute("PRAGMA synchronous=FULL")
    # Enable foreign key constraints
    cursor.execute("PRAGMA foreign_keys=ON")
    # Set a reasonable timeout for busy database
    cursor.execute("PRAGMA busy_timeout=30000")  # 30 seconds
    cursor.close()

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create declarative base class for models
Base = declarative_base()

class RefinementJobORM(Base):
    __tablename__ = "refinement_jobs"

    # Primary key
    job_id = Column(String, primary_key=True, index=True)
    
    # Request fields
    file_id = Column(Integer, nullable=False, index=True)
    refiner_id = Column(Integer, nullable=False, index=True)
    encryption_key = Column(String, nullable=False)
    env_vars = Column(Text, nullable=True)  # JSON string
    
    # Status fields
    status = Column(String, nullable=False, index=True)
    error = Column(Text, nullable=True)
    
    # Result fields
    transaction_hash = Column(String, nullable=True)
    
    # Processing details
    docker_container_name = Column(String, nullable=True)
    docker_exit_code = Column(Integer, nullable=True)
    docker_logs = Column(Text, nullable=True)
    
    # Timing fields
    submitted_at = Column(DateTime, nullable=False, server_default=func.now())
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    
    # Metadata
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(DateTime, nullable=False, server_default=func.now(), 
                       onupdate=func.now())

    __table_args__ = (
        Index('idx_refinement_jobs_file_id', 'file_id'),
        Index('idx_refinement_jobs_refiner_id', 'refiner_id'),
        Index('idx_refinement_jobs_status', 'status'),
        Index('idx_refinement_jobs_submitted_at', 'submitted_at'),
    )

# Create tables if they don't exist
def initialize_database():
    """Initialize the database schema."""
    try:
        logger.info(f"Initializing refiner database at {STORES_DB_PATH}")
        Base.metadata.create_all(bind=engine)
        logger.info("Refiner database schema initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing refiner database schema: {e}")
        raise

def verify_wal_mode():
    """Verify that WAL mode is properly enabled"""
    try:
        with get_db_session() as session:
            result = session.execute(text("PRAGMA journal_mode")).fetchone()
            journal_mode = result[0] if result else "unknown"
            
            result = session.execute(text("PRAGMA synchronous")).fetchone()
            sync_mode = result[0] if result else "unknown"
            
            logger.info(f"SQLite configuration: journal_mode={journal_mode}, synchronous={sync_mode}")
            
            if journal_mode.lower() == "wal":
                logger.info("✅ WAL mode is properly enabled for better concurrent access")
                return True
            else:
                logger.warning(f"⚠️ WAL mode not enabled, current mode: {journal_mode}")
                return False
    except Exception as e:
        logger.error(f"Failed to verify WAL mode: {e}")
        return False

@contextmanager
def get_db_session() -> Generator[Session, None, None]:
    """
    Context manager to handle database sessions.
    
    Example usage:
    ```
    with get_db_session() as session:
        # Use session here
        session.query(...)
    ```
    
    Yields:
        SQLAlchemy session
    """
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception as e:
        session.rollback()
        logger.error(f"Database session error: {e}")
        raise
    finally:
        session.close()

def session_scope(func: Callable):
    """
    Decorator that provides a session only if one isn't already provided
    
    Example usage:
    ```
    @session_scope
    def my_func(session, arg1, arg2):
        # Use session here
        session.query(...)
    ```
    """
    def wrapper(*args, session=None, **kwargs):
        if session is not None:
            return func(session, *args, **kwargs)
        else:
            with get_db_session() as new_session:
                return func(new_session, *args, **kwargs)
    return wrapper 

# Initialize database and verify WAL mode
initialize_database()
verify_wal_mode()