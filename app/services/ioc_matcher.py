from collections.abc import Iterator, Mapping

from pydantic import BaseModel, ConfigDict

from app.models.ioc import IOC, IOCType


class IOCMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ioc_id: str
    ioc_type: IOCType
    ioc_value: str
    field: str
    observed_value: str


class IOCMatcher:
    def match(
        self,
        iocs: list[IOC],
        event: Mapping[str, object],
    ) -> list[IOCMatch]:
        matches: list[IOCMatch] = []

        for field, value in self._iter_values(event):
            if not isinstance(value, str):
                continue

            for ioc in iocs:
                if self._normalize(ioc.type, value) != self._normalize(
                    ioc.type,
                    ioc.value,
                ):
                    continue

                matches.append(
                    IOCMatch(
                        ioc_id=ioc.id,
                        ioc_type=ioc.type,
                        ioc_value=ioc.value,
                        field=field,
                        observed_value=value,
                    )
                )

        return matches

    @staticmethod
    def _normalize(ioc_type: IOCType, value: str) -> str:
        if ioc_type in {
            IOCType.DOMAIN,
            IOCType.EMAIL,
            IOCType.HASH,
            IOCType.URL,
        }:
            return value.lower()

        return value

    @classmethod
    def _iter_values(
        cls,
        value: object,
        field: str = "",
    ) -> Iterator[tuple[str, object]]:
        if isinstance(value, Mapping):
            for key, nested_value in value.items():
                nested_field = f"{field}.{key}" if field else str(key)
                yield from cls._iter_values(nested_value, nested_field)
            return

        if isinstance(value, list):
            for index, nested_value in enumerate(value):
                nested_field = f"{field}[{index}]"
                yield from cls._iter_values(nested_value, nested_field)
            return

        yield field, value
