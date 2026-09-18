from app.models.evidence import Evidence
from app.models.timeline import TimelineEvent


class TimelineBuilder:
    def build(self, evidence: list[Evidence]) -> list[TimelineEvent]:
        events = [
            TimelineEvent(
                id=f"TL-{item.id}",
                case_id=item.case_id,
                timestamp=item.collected_at,
                event_type=item.type,
                source=item.source,
                description=item.description or item.value,
                evidence_id=item.id,
            )
            for item in evidence
        ]

        return sorted(
            events,
            key=lambda event: (event.timestamp, event.id),
        )
