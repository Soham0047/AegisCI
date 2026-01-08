from __future__ import annotations

from bisect import bisect_left, bisect_right
from dataclasses import dataclass


@dataclass(frozen=True)
class Span:
    filepath: str
    start_line: int
    end_line: int
    sample_id: str

    @property
    def length(self) -> int:
        return self.end_line - self.start_line


class SpanIndex:
    def __init__(self, spans: list[Span]):
        self.spans = sorted(spans, key=lambda s: (s.start_line, s.end_line))
        self.starts = [s.start_line for s in self.spans]

    def match_enclosing(self, line: int) -> str | None:
        idx = bisect_right(self.starts, line) - 1
        best: Span | None = None
        while idx >= 0:
            span = self.spans[idx]
            if span.start_line > line:
                idx -= 1
                continue
            if best and (line - span.start_line) > best.length:
                break
            if span.end_line >= line:
                if not best or span.length < best.length:
                    best = span
            idx -= 1
        return best.sample_id if best else None

    def match_nearest(self, line: int, max_distance: int) -> str | None:
        left = bisect_left(self.starts, line - max_distance)
        right = bisect_right(self.starts, line + max_distance)
        candidates = self.spans[max(0, left - 1) : min(len(self.spans), right + 1)]
        best: Span | None = None
        best_distance: int | None = None
        for span in candidates:
            if span.start_line <= line <= span.end_line:
                return span.sample_id
            if line < span.start_line:
                distance = span.start_line - line
            else:
                distance = line - span.end_line
            if distance > max_distance:
                continue
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best = span
        return best.sample_id if best else None


def build_span_index(samples: list[dict]) -> dict[tuple[str, str], SpanIndex]:
    by_file: dict[tuple[str, str], list[Span]] = {}
    for sample in samples:
        repo = sample.get("repo")
        filepath = sample.get("filepath")
        span = sample.get("function_span") or {}
        start = span.get("start_line")
        end = span.get("end_line")
        if not repo or not filepath or not start or not end:
            continue
        key = (repo, filepath)
        by_file.setdefault(key, []).append(
            Span(filepath=filepath, start_line=start, end_line=end, sample_id=sample["sample_id"])
        )
    return {key: SpanIndex(spans) for key, spans in by_file.items()}


def match_by_enclosing_span(
    index: dict[tuple[str, str], SpanIndex], repo: str, filepath: str, line: int
) -> str | None:
    span_index = index.get((repo, filepath))
    if not span_index:
        return None
    return span_index.match_enclosing(line)


def match_nearest_span(
    index: dict[tuple[str, str], SpanIndex],
    repo: str,
    filepath: str,
    line: int,
    max_distance: int = 3,
) -> str | None:
    span_index = index.get((repo, filepath))
    if not span_index:
        return None
    return span_index.match_nearest(line, max_distance=max_distance)
