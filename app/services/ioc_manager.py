from app.models.ioc import IOC


class IOCManager:
    def __init__(self) -> None:
        self._iocs: dict[str, IOC] = {}

    def create(self, ioc: IOC) -> IOC:
        if any(
            existing.type == ioc.type and existing.value == ioc.value
            for existing in self._iocs.values()
        ):
            raise ValueError("IOC already exists")

        self._iocs[ioc.id] = ioc
        return ioc

    def get(self, ioc_id: str) -> IOC | None:
        return self._iocs.get(ioc_id)

    def list(self) -> list[IOC]:
        return list(self._iocs.values())

    def delete(self, ioc_id: str) -> bool:
        return self._iocs.pop(ioc_id, None) is not None
