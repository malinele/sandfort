"""Tables ``webhook_endpoints`` and ``webhook_deliveries`` (WP 4.2).

``secret`` holds the server-side encrypted signing secret, never the plaintext.
One delivery row exists per (endpoint, event) pair, which keeps fan-out idempotent.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from sandfort.db.base import Base, TimestampMixin, utcnow
from sandfort.db.support import in_check


class DeliveryState(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    DISABLED = "disabled"


class WebhookEndpointRow(Base):
    __tablename__ = "webhook_endpoints"

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    org_id: Mapped[str] = mapped_column(String(30), ForeignKey("organizations.id"), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    secret: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    event_types: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )


class WebhookDeliveryRow(TimestampMixin, Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        CheckConstraint(in_check("state", DeliveryState), name="state"),
        UniqueConstraint(
            "endpoint_id", "event_id", name="uq_webhook_deliveries_endpoint_id_event_id"
        ),
        Index("ix_webhook_deliveries_state_next_attempt_at", "state", "next_attempt_at"),
    )

    id: Mapped[str] = mapped_column(String(30), primary_key=True)
    endpoint_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("webhook_endpoints.id"), nullable=False
    )
    event_id: Mapped[str] = mapped_column(
        String(30), ForeignKey("outbox_events.id"), nullable=False
    )
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Delivery detail (round 60). NULL on rows written before migration 0022; the dispatcher
    # fills ``event_type`` and ``payload_sha256`` on the first attempt of such a row.
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    payload_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)  # hash only
    last_error: Mapped[str | None] = mapped_column(String(200), nullable=True)
    attempt_history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, nullable=False, default=list, server_default=text("'[]'")
    )
