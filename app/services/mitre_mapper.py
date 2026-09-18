from app.models.evidence import Evidence
from app.models.mitre import MITREMapping, MITRETactic, MITRETechnique


class MITREMapper:
    _TECHNIQUES = (
        MITRETechnique(
            id="T1110",
            name="Brute Force",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
        ),
        MITRETechnique(
            id="T1110.003",
            name="Password Spraying",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
        ),
        MITRETechnique(
            id="T1059",
            name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
        ),
        MITRETechnique(
            id="T1059.001",
            name="PowerShell",
            tactic=MITRETactic.EXECUTION,
        ),
        MITRETechnique(
            id="T1059.003",
            name="Windows Command Shell",
            tactic=MITRETactic.EXECUTION,
        ),
        MITRETechnique(
            id="T1059.004",
            name="Unix Shell",
            tactic=MITRETactic.EXECUTION,
        ),
    )

    _RULES = (
        (
            ("password spraying",),
            "T1110.003",
            95,
            "Evidence explicitly describes password spraying activity.",
        ),
        (
            ("brute force", "brute-force", "bruteforce"),
            "T1110",
            90,
            "Evidence describes brute-force authentication activity.",
        ),
        (
            ("powershell",),
            "T1059.001",
            95,
            "Evidence contains a PowerShell execution indicator.",
        ),
        (
            ("cmd.exe", "windows command shell"),
            "T1059.003",
            95,
            "Evidence contains a Windows command shell indicator.",
        ),
        (
            ("unix shell", "/bin/bash", "/bin/sh", "bash "),
            "T1059.004",
            90,
            "Evidence contains a Unix shell execution indicator.",
        ),
    )

    def map_evidence(self, evidence: Evidence) -> list[MITREMapping]:
        text = f"{evidence.description} {evidence.value}".lower()
        mappings: list[MITREMapping] = []

        for keywords, technique_id, confidence, rationale in self._RULES:
            if not any(keyword in text for keyword in keywords):
                continue

            technique = self._get_technique(technique_id)
            if technique is None:
                continue

            mappings.append(
                MITREMapping(
                    evidence_id=evidence.id,
                    technique=technique,
                    confidence=confidence,
                    rationale=rationale,
                )
            )

        return mappings

    def map_many(self, evidence: list[Evidence]) -> list[MITREMapping]:
        mappings: list[MITREMapping] = []

        for item in evidence:
            mappings.extend(self.map_evidence(item))

        return mappings

    @classmethod
    def _get_technique(cls, technique_id: str) -> MITRETechnique | None:
        return next(
            (
                technique
                for technique in cls._TECHNIQUES
                if technique.id == technique_id
            ),
            None,
        )
