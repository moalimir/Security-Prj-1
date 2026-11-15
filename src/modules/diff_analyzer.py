"""Correlate symbolized execution frames with changed source lines/functions."""
import re
import subprocess
from pathlib import Path

from unidiff import PatchSet
from unidiff.errors import UnidiffParseError

from src.utils.exceptions import AnalysisError


class DiffAnalyzer:
    def __init__(self, repo_path: Path):
        self.repo_path = Path(repo_path)

    def analyze(self, base_commit: str, patched_commit: str) -> dict:
        try:
            proc = subprocess.run(["git", "-c", f"safe.directory={self.repo_path}", "diff", "--no-ext-diff", "--no-color", "--unified=3",
                                   base_commit, patched_commit, "--"], cwd=self.repo_path,
                                  capture_output=True, text=True, errors="replace", check=True)
            patch = PatchSet(proc.stdout)
        except (OSError, subprocess.CalledProcessError, UnidiffParseError) as exc:
            raise AnalysisError(f"Cannot analyze source diff: {exc}") from exc
        files = []
        for file in patch:
            files.append({"base_path": file.source_file.removeprefix("a/"),
                          "patched_path": file.target_file.removeprefix("b/"),
                          "hunks": [{"context": h.section_header,
                                     "base_lines": [line.source_line_no for line in h if line.is_removed],
                                     "patched_lines": [line.target_line_no for line in h if line.is_added]}
                                    for h in file]})
        return {"patch": proc.stdout, "files": files}

    @staticmethod
    def map_signature(signature: tuple, report: dict) -> tuple | None:
        """Map an unchanged baseline error site into the patched source."""
        error_type, mechanism, location = signature
        if location is None:
            return signature
        path, function, line_number = location
        for file in PatchSet(report["patch"]):
            if file.source_file.removeprefix("a/") != path:
                continue
            if file.is_removed_file:
                return None
            patched_path = file.target_file.removeprefix("b/")
            offset = 0
            for hunk in file:
                if line_number < hunk.source_start or (hunk.source_length == 0 and line_number == hunk.source_start):
                    break
                for line in hunk:
                    if line.source_line_no == line_number:
                        # A changed/deleted site cannot establish error identity.
                        if line.is_removed:
                            return None
                        return error_type, mechanism, (patched_path, function, line.target_line_no)
                offset = hunk.target_start + hunk.target_length - hunk.source_start - hunk.source_length
            return error_type, mechanism, (patched_path, function, line_number + offset)
        return signature

    @staticmethod
    def correlate(frames, report: dict, side: str, source_dir: Path) -> dict:
        matches = []
        primary, previous = True, -1
        for frame in frames:
            # Allocation/free traces restart numbering; do not call them crash frames.
            if frame.frame_id <= previous:
                primary = False
            previous = frame.frame_id
            role = ("crash" if frame.frame_id == 0 else "caller") if primary else "auxiliary"
            frame_evidence = {"frame_id": frame.frame_id, "frame_role": role}
            path = Path(frame.file_path)
            if path.is_absolute():
                try:
                    path = path.relative_to(source_dir)
                except ValueError:
                    continue
            for file in report.get("files", []):
                if path.as_posix() != file[f"{side}_path"]:
                    continue
                for hunk in file["hunks"]:
                    if frame.line_number in hunk[f"{side}_lines"]:
                        matches.append({"status": "changed_line", "file": str(path),
                                        "line": frame.line_number, "function": frame.function_name, **frame_evidence})
                    elif re.search(r"\b" + re.escape(frame.function_name) + r"\s*\(", hunk["context"]):
                        matches.append({"status": "same_function", "file": str(path),
                                        "line": frame.line_number, "function": frame.function_name, **frame_evidence})
        status = "changed_line" if any(m["status"] == "changed_line" for m in matches) else "same_function" if matches else "unknown"
        return {"status": status, "evidence": matches,
                "limitation": "Runtime location overlap is evidence of association, not proof of causation; caller effects may be unknown."}
