"""The sqlite3 connection class behind every SQLite engine: it rolls back before it closes.

Every transaction starts with ``BEGIN IMMEDIATE`` (``sandfort.db.engine``), so it holds the
database write lock from its first statement. When a task is cancelled while one of its
statements still runs in the aiosqlite thread, SQLAlchemy closes the connection without a
``ROLLBACK``. sqlite3 cannot finish that close while a cursor still holds the unfinished
statement (``sqlite3_close_v2`` defers it), so the transaction and the write lock stayed open
until the cancelled task was garbage collected, and every other writer waited out
``busy_timeout``. Worker shutdown cancels each worker loop and hit exactly this.

Rolling back first ends the transaction, and with it the lock, whether or not the close itself
completes. aiosqlite runs ``close`` in its connection thread on both the graceful path and the
forced stop, so the rollback runs where the connection lives.
"""

import logging
import sqlite3

logger = logging.getLogger(__name__)


class RollbackOnCloseConnection(sqlite3.Connection):
    """A ``sqlite3.Connection`` whose ``close`` ends an open transaction first."""

    def close(self) -> None:
        try:
            if self.in_transaction:
                self.rollback()
        except sqlite3.Error:
            logger.exception("rollback before close failed; closing anyway")
        finally:
            super().close()
