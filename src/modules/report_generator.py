"""Durable JSON evidence and escaped, human-readable summaries."""
import html
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path


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
        cell = lambda value: str(value).replace("\n", " ").replace("|", "\\|")
        lines = [f"# {cell(data['project'])}", "", f"Exit code: **{data['exit_code']}**", "",
                 "Conclusions apply only to these tests and build settings.", "",
                 "| Test | Classification | Evidence |", "| --- | --- | --- |"]
        for f in findings:
            lines.append(f"| {cell(f['test_name'])} | {cell(f['category'])} | {cell(f['detail'])} |")
        for error in data.get("errors", []):
            lines.extend(["", f"Error: {cell(error)}"])
        for warning in data.get("warnings", []):
            lines.extend(["", f"Warning: {cell(warning)}"])
        markdown = "\n".join(lines) + "\n"
        (self.output_dir / "report.md").write_text(markdown, encoding="utf-8")
        summary = html.escape(markdown)
        evidence = html.escape(json.dumps(data, indent=2, default=json_default))
        (self.output_dir / "report.html").write_text(
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Patch validation report</title><style>'
            'body{max-width:1100px;margin:3rem auto;padding:0 1rem;font:16px system-ui;line-height:1.5}'
            'pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f5f7;padding:1rem}'
            '</style><h1>Patch validation report</h1><pre>' + summary + '</pre>'
            '<details><summary>Complete execution evidence</summary><pre>' + evidence + '</pre></details></html>',
            encoding="utf-8",
        )
