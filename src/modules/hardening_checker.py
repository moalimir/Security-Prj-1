"""Evidence from ELF headers and symbols, without claims about runtime ASLR."""
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.dynamic import DynamicSection
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from src.utils.exceptions import AnalysisError


class HardeningChecker:
    def check(self, binary_path: Path) -> dict:
        result = {"status": "unsupported", "relro": None, "nx": None, "pie": None,
                  "canary": None, "fortify": None, "evidence": []}
        try:
            with Path(binary_path).open("rb") as stream:
                if stream.read(4) != b"\x7fELF":
                    result["evidence"].append("Not an ELF binary; run the Linux container for course validation.")
                    return result
                stream.seek(0)
                elf = ELFFile(stream)
                segments = list(elf.iter_segments())
                dynamic_tags = [tag for section in elf.iter_sections() if isinstance(section, DynamicSection)
                                for tag in section.iter_tags()]
                bind_now = any(tag.entry.d_tag == "DT_BIND_NOW"
                               or (tag.entry.d_tag == "DT_FLAGS" and tag.entry.d_val & 8)
                               or (tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 1)
                               for tag in dynamic_tags)
                has_relro = any(s.header.p_type == "PT_GNU_RELRO" for s in segments)
                stack = next((s for s in segments if s.header.p_type == "PT_GNU_STACK"), None)
                symbols = {symbol.name for section in elf.iter_sections() if isinstance(section, SymbolTableSection)
                           for symbol in section.iter_symbols()}
                pie = elf.header.e_type == "ET_DYN" and (
                    any(s.header.p_type == "PT_INTERP" for s in segments)
                    or any(t.entry.d_tag == "DT_FLAGS_1" and t.entry.d_val & 0x08000000 for t in dynamic_tags))
                result.update(status="checked" if stack else "inconclusive",
                              relro="full" if has_relro and bind_now else "partial" if has_relro else "none",
                              nx=not bool(stack.header.p_flags & 1) if stack else None,
                              pie=bool(pie), canary="__stack_chk_fail" in symbols,
                              fortify=any(name.startswith("__") and name.endswith("_chk")
                                          and name != "__stack_chk_fail" for name in symbols),
                              evidence=[f"ELF type: {elf.header.e_type}", f"PT_GNU_RELRO: {has_relro}",
                                        f"BIND_NOW flags: {bind_now}",
                                        f"PT_GNU_STACK flags: {stack.header.p_flags if stack else 'missing'}",
                                        "Canary/Fortify results indicate symbol presence, not coverage of every function.",
                                        "PIE does not establish that runtime ASLR is enabled."])
        except (OSError, ELFError) as exc:
            raise AnalysisError(f"Cannot inspect ELF binary {binary_path}: {exc}") from exc
        return result

    @staticmethod
    def compare(base: dict, patched: dict) -> list[str]:
        warnings = []
        if base["status"] != "checked" or patched["status"] != "checked":
            warnings.append("ELF hardening could not be checked for both release binaries.")
        for key in ("nx", "pie", "canary", "fortify"):
            if base[key] is True and patched[key] is False:
                warnings.append(f"Hardening decreased: {key} ({base[key]} -> {patched[key]}).")
        ranks = {"none": 0, "partial": 1, "full": 2}
        if (base["relro"] in ranks and patched["relro"] in ranks
                and ranks[patched["relro"]] < ranks[base["relro"]]):
            warnings.append(f"Hardening decreased: RELRO ({base['relro']} -> {patched['relro']}).")
        return warnings
