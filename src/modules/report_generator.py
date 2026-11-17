"""Durable JSON evidence and escaped, human-readable summaries."""
import html
import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path


def new_report() -> dict:
    return {"schema_version": 1, "project": "unresolved", "exit_code": 40,
            "security_status": "inconclusive", "functionality_status": "inconclusive",
            "analysis_complete": False, "started_at": datetime.now(timezone.utc).isoformat(),
            "warnings": [], "errors": [], "findings": [],
            "builds": {}, "results": {}, "hardening": {}, "diff": {}}


def json_default(value):
    if is_dataclass(value):
        return asdict(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def write_json(path: Path, data) -> None:
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, default=json_default) + "\n", encoding="utf-8")
    temp.replace(path)


class ReportGenerator:
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)

    def generate(self, data: dict) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        write_json(self.output_dir / "report.json", data)
        findings = [asdict(f) if is_dataclass(f) else f for f in data.get("findings", [])]
        lines, sections = [], []

        def display(value):
            if value is None:
                return "unknown"
            if isinstance(value, bool):
                return "yes" if value else "no"
            return str(value) if value != "" else "(empty)"

        def cell(value):
            escaped = html.escape(display(value)).replace("\r\n", "\n").replace("\r", "\n")
            return re.sub(r"([\\`*_{}\[\]|])", r"\\\1", escaped).replace("\n", "<br>")

        def heading(level, title):
            lines.extend([f"{'#' * level} {cell(title)}", ""])
            sections.append(f"<h{level}>{html.escape(display(title))}</h{level}>")

        def paragraph(value):
            lines.extend([cell(value), ""])
            sections.append(f"<p>{html.escape(display(value))}</p>")

        def table(headers, rows, empty="No execution data recorded."):
            if not rows:
                paragraph(empty)
                return
            lines.extend(["| " + " | ".join(map(cell, headers)) + " |",
                          "| " + " | ".join("---" for _ in headers) + " |"])
            lines.extend("| " + " | ".join(map(cell, row)) + " |" for row in rows)
            lines.append("")
            sections.append('<div class="table-wrap"><table><thead><tr>' + "".join(
                f'<th scope="col">{html.escape(header)}</th>' for header in headers) + "</tr></thead><tbody>")
            for row in rows:
                cells = []
                for header, value in zip(headers, row):
                    value = html.escape(display(value))
                    value = f"<pre>{value}</pre>" if header in ("stdout", "stderr", "Stack frames") else value
                    cells.append(f"<td>{value}</td>")
                sections.append("<tr>" + "".join(cells) + "</tr>")
            sections.append("</tbody></table></div>")

        heading(1, data["project"])
        paragraph(f"Exit code: {data['exit_code']}")
        paragraph("Conclusions apply only to these tests and build settings.")
        heading(2, "Combined Verdict")
        table(["Test", "Combined verdict", "Release verdict", "Instrumented verdict"], [
            [f["test_name"], f["category"],
             f.get("comparisons", {}).get("release", {}).get("category", "Not recorded"),
             f.get("comparisons", {}).get("sanitized", {}).get("category", "Not recorded")]
            for f in findings], empty="No findings recorded.")
        for finding in findings:
            if not finding.get("comparisons") and finding.get("detail"):
                paragraph(f"{finding['test_name']}: {finding['detail']}")
        for mode, title in (("release", "Release Build Summary"),
                            ("sanitized", "Instrumented (ASan/UBSan) Build Summary")):
            heading(2, title)
            if mode == "release":
                heading(3, "ELF Hardening")
                hardening = data.get("hardening", {})
                rows = []
                for side in ("base", "patched"):
                    checked = hardening.get(side, hardening)
                    rows.append([side.title(), checked.get("status", "Not recorded"),
                                 *[checked.get(key) for key in ("relro", "nx", "pie", "canary", "fortify")],
                                 "\n".join(checked.get("evidence", [])) or "Not recorded"])
                table(["Binary", "Status", "RELRO", "NX", "PIE", "Canary", "Fortify", "Evidence"], rows)
            table(["Test", "Classification", "Stable replays", "Evidence"], [
                [f["test_name"], f.get("comparisons", {}).get(mode, {}).get("category", "Not recorded"),
                 f.get("comparisons", {}).get(mode, {}).get("stable"),
                 f.get("comparisons", {}).get(mode, {}).get("detail", "Not recorded")]
                for f in findings], empty="No comparisons recorded.")
            mode_results = {side: data.get("results", {}).get(f"{side}_{mode}", {}) for side in ("base", "patched")}
            names = dict.fromkeys([f["test_name"] for f in findings] + [
                name for results in mode_results.values() for name in results])
            headers = ["Test", "Binary", "Run", "Exit code", "Signal", "Execution status"]
            if mode == "sanitized":
                headers += ["Error type", "Detection mechanism", "Stack frames"]
            headers += ["stdout", "stderr"]
            rows = []
            for name in names:
                for side, results in mode_results.items():
                    for number, result in enumerate(results.get(name, []) or [None], 1):
                        if result is None:
                            rows.append([name, side.title(), *["Not recorded"] * (len(headers) - 2)])
                            continue
                        result = asdict(result) if is_dataclass(result) else result
                        if result.get("timed_out"):
                            status = "Timed out"
                        elif result.get("resource_limited") or result.get("oom_killed"):
                            status = "Resource/runtime failure"
                        elif result.get("error_type") or result.get("signal"):
                            status = "Crash"
                        else:
                            status = "Exited" if "exit_code" in result else "Not recorded"
                        row = [name, side.title(), number, result.get("exit_code", "Not recorded"),
                               result.get("signal", "Not recorded") or "none", status]
                        if mode == "sanitized":
                            frames = (result.get("sanitizer_report") or {}).get("stack_frames", [])
                            stack = "\n".join(f"#{frame['frame_id']} {frame['function_name']} ({frame['file_path']}:{frame['line_number']})"
                                              for frame in frames) or "none recorded"
                            row += [result.get("error_type", "Not recorded") or "none",
                                    result.get("detection_mechanism", "Not recorded") or "none", stack]
                        row += [result.get("stdout", "Not recorded"), result.get("stderr", "Not recorded")]
                        rows.append(row)
            table(headers, rows)
            heading(3, "Diff Correlation")
            rows = []
            for finding in findings:
                for side in ("base", "patched"):
                    correlation = finding.get("correlation", {}).get(f"{side}_{mode}", {})
                    for match in correlation.get("evidence", []) or [None]:
                        evidence = "No matching symbolized frame recorded."
                        if match is not None:
                            role = match.get("frame_role", "unknown")
                            frame = match.get("frame_id", "unknown")
                            evidence = (f"{match['status']} ({role} frame #{frame}: {match['function']})\n"
                                        f"{match['file']}:{match['line']}")
                        rows.append([finding["test_name"], side.title(), correlation.get("status", "unknown"),
                                     evidence, correlation.get("limitation", "Association is not proof of causation.")])
            table(["Test", "Binary", "Correlation", "Frame evidence", "Limitation"], rows,
                  empty="No correlation evidence recorded.")
        for error in data.get("errors", []):
            paragraph(f"Error: {error}")
        for warning in data.get("warnings", []):
            paragraph(f"Warning: {warning}")
        markdown = "\n".join(lines) + "\n"
        (self.output_dir / "report.md").write_text(markdown, encoding="utf-8")
        evidence = html.escape(json.dumps(data, indent=2, default=json_default))
        (self.output_dir / "report.html").write_text(
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Patch validation report</title><style>'
            'body{max-width:1200px;margin:3rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5;color:#172b3a}'
            'h2{margin-top:3rem;border-top:3px solid #256477;padding-top:1rem}'
            '.table-wrap{overflow-x:auto;margin:1rem 0 2rem}table{border-collapse:collapse;width:100%;font-size:14px}'
            'th,td{border:1px solid #c9d2d8;padding:.6rem;text-align:left;vertical-align:top;white-space:pre-wrap}'
            'th{background:#eaf0f3}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:.7rem}'
            'td pre{margin:0;min-width:10rem;max-width:28rem;max-height:18rem;overflow:auto}'
            '</style></head><body>' + "".join(sections) +
            '<details><summary>Complete execution evidence</summary><pre>' + evidence + '</pre></details></body></html>',
            encoding="utf-8",
        )
