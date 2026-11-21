"""HTML extraction that keeps track of which text a browser would actually show.

The parser is deliberately simple and forgiving: it is a stack over the standard library's
HTMLParser, plus a small CSS reader for inline styles and simple selectors in <style> blocks
(`.class`, `#id`, `tag`, and comma-separated lists of those). It does not lay out the page, so
it cannot see text covered by other elements; see docs/limitations in the README.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

from rag_vet.models import Link, Segment

VOID = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr",
}  # fmt: skip
SKIP = {"script", "style", "noscript"}
INLINE = {
    "a", "abbr", "b", "bdi", "bdo", "cite", "code", "data", "dfn", "em", "font", "i", "kbd", "label", "mark", "q",
    "s", "samp", "small", "span", "strong", "sub", "sup", "time", "u", "var",
}  # fmt: skip
HIDDEN_TAGS = {"template": "<template> element"}
ATTRS = {"alt": "alt text", "title": "title attribute", "aria-label": "aria-label attribute"}

_DECL = re.compile(r"([a-zA-Z-]+)\s*:\s*([^;]+)")
_RULE = re.compile(r"([^{}]+)\{([^{}]*)\}")
_SIMPLE_SELECTOR = re.compile(r"^(?:[a-zA-Z][\w-]*|\.[\w-]+|#[\w-]+)$")
_LENGTH = re.compile(r"^(-?\d*\.?\d+)\s*(px|pt|em|rem|%)?$")
_WHITE = {"white", "#fff", "#ffffff", "#fffffe", "rgb(255,255,255)", "rgba(255,255,255,1)", "hsl(0,0%,100%)"}
_TRANSPARENT = re.compile(r"^(transparent|rgba\(.*,\s*0(\.0+)?\)|hsla\(.*,\s*0(\.0+)?\)|#[0-9a-f]{6}00|#[0-9a-f]{3}0)$")


def parse_declarations(style: str) -> dict[str, str]:
    return {k.lower(): v.strip().lower() for k, v in _DECL.findall(style)}


def parse_stylesheet(css: str) -> dict[str, dict[str, str]]:
    """Map simple selectors to their declarations. Complex selectors are ignored."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    rules: dict[str, dict[str, str]] = {}
    for selectors, body in _RULE.findall(css):
        decls = parse_declarations(body)
        for sel in selectors.split(","):
            sel = sel.strip()
            if _SIMPLE_SELECTOR.match(sel):
                rules.setdefault(sel.lower(), {}).update(decls)
    return rules


def _length(value: str) -> float | None:
    """A CSS length in px, roughly. Relative units are treated as multiples of 16px."""
    m = _LENGTH.match(value.replace("!important", "").strip())
    if not m:
        return None
    number, unit = float(m.group(1)), m.group(2) or "px"
    return number * {"px": 1.0, "pt": 1.33, "em": 16.0, "rem": 16.0, "%": 0.16}[unit]


def _norm_color(value: str) -> str:
    return re.sub(r"\s+", "", value.replace("!important", ""))


def hidden_reason(decls: dict[str, str]) -> str | None:
    """Why text styled with these declarations would be invisible, or None."""
    display = decls.get("display", "")
    if display.startswith("none"):
        return "display:none"
    if decls.get("visibility", "").startswith(("hidden", "collapse")):
        return "visibility:hidden"
    opacity = decls.get("opacity", "").replace("!important", "").strip()
    if opacity:
        try:
            if float(opacity.rstrip("%")) <= 0.01:
                return "opacity:0"
        except ValueError:
            pass
    size = _length(decls.get("font-size", "x"))
    if size is not None and size < 2:
        return f"font-size:{decls['font-size']}"
    for prop in ("left", "top", "text-indent", "margin-left", "right"):
        value = _length(decls.get(prop, "x"))
        if value is not None and value <= -999:
            return f"positioned off-screen ({prop}:{decls[prop]})"
    clip = decls.get("clip", "").replace(" ", "")
    if (clip.startswith("rect(0") and clip.count("0") >= 4) or decls.get("clip-path", "").startswith("inset(50%"):
        return "clipped to nothing (visually hidden)"
    for prop in ("height", "width", "max-height", "max-width"):
        value = _length(decls.get(prop, "x"))
        if value is not None and value <= 1 and decls.get("overflow", "").startswith("hidden"):
            return f"{prop}:{decls[prop]} with overflow:hidden"
    color = _norm_color(decls.get("color", ""))
    if color and _TRANSPARENT.match(color):
        return "transparent text"
    background = _norm_color(decls.get("background-color", decls.get("background", "")))
    if color and background and color == background:
        return f"text colour matches background ({color})"
    return None


class _Frame:
    __slots__ = ("background", "color", "reason", "tag")

    def __init__(self, tag: str, reason: str | None, color: str | None, background: str | None) -> None:
        self.tag = tag
        self.reason = reason
        self.color = color
        self.background = background


class VisibilityParser(HTMLParser):
    def __init__(self, line_offset: int = 0) -> None:
        super().__init__(convert_charrefs=True)
        self.segments: list[Segment] = []
        self.links: list[Link] = []
        self.stack: list[_Frame] = []
        self._open: dict[str, int] = {}
        self.sheet: dict[str, dict[str, str]] = {}
        self.line_offset = line_offset
        self._skip_depth = 0
        self._style_buf: list[str] | None = None
        self._break = False

    # -- state helpers ---------------------------------------------------------------
    def _line(self) -> int:
        return self.getpos()[0] + self.line_offset

    def _current(self) -> tuple[str | None, str | None, str | None]:
        """Effective (inherited) state. Each frame stores it, so this is O(1) at any nesting depth."""
        if not self.stack:
            return None, None, None
        top = self.stack[-1]
        return top.reason, top.color, top.background

    def _emit(self, text: str, hidden_reason: str | None) -> None:
        if not text:
            return
        hidden = hidden_reason is not None
        reason = hidden_reason or ""
        line = self._line()
        last = self.segments[-1] if self.segments else None
        if last is not None and last.hidden == hidden and last.reason == reason and last.line is not None:
            separator = "\n" if self._break and not last.text.endswith("\n") and not text.startswith("\n") else ""
            last.text += separator + text
            self._break = False
            return
        self._break = False
        self.segments.append(Segment(text, location=f"line {line}", line=line, hidden=hidden, reason=reason))

    def _declarations(self, tag: str, attrs: dict[str, str]) -> dict[str, str]:
        decls: dict[str, str] = {}
        decls.update(self.sheet.get(tag, {}))
        for cls in attrs.get("class", "").split():
            decls.update(self.sheet.get(f".{cls.lower()}", {}))
        if attrs.get("id"):
            decls.update(self.sheet.get(f"#{attrs['id'].lower()}", {}))
        # Presentational attributes from old HTML, such as <font color="white">.
        if attrs.get("color"):
            decls["color"] = attrs["color"].lower()
        if attrs.get("bgcolor"):
            decls["background-color"] = attrs["bgcolor"].lower()
        decls.update(parse_declarations(attrs.get("style", "")))
        return decls

    # -- HTMLParser hooks ------------------------------------------------------------
    def handle_starttag(self, tag: str, attrs_list: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag not in INLINE:
            self._break = True
        attrs = {k.lower(): (v or "") for k, v in attrs_list}
        if tag == "style":
            self._style_buf = []
        if tag in SKIP:
            self._skip_depth += 1
            return
        line = self._line()
        if tag in ("a", "area") and attrs.get("href"):
            self.links.append(Link(attrs["href"], f"line {line}", line, image=False))
        if tag in ("img", "image", "source") and (attrs.get("src") or attrs.get("srcset")):
            self.links.append(Link(attrs.get("src") or attrs["srcset"], f"line {line}", line, image=True))
        if tag == "meta" and attrs.get("content") and (attrs.get("name") or attrs.get("property")):
            label = attrs.get("name") or attrs.get("property")
            self.segments.append(Segment(attrs["content"], f"<meta {label}>", line, hidden=True, reason="meta tag"))
        for attr, label in ATTRS.items():
            if attrs.get(attr):
                self.segments.append(Segment(attrs[attr], f"line {line}", line, hidden=True, reason=label))
        if tag in VOID:
            return
        decls = self._declarations(tag, attrs)
        reason = hidden_reason(decls)
        if reason is None and "hidden" in attrs:
            reason = "hidden attribute"
        if reason is None and tag in HIDDEN_TAGS:
            reason = HIDDEN_TAGS[tag]
        color = _norm_color(decls["color"]) if "color" in decls else None
        background = decls.get("background-color") or decls.get("background")
        background = _norm_color(background) if background else None
        if reason is None and color:
            _, _, inherited_bg = self._current()
            bg = background or inherited_bg
            if bg and bg == color:
                reason = f"text colour matches background ({color})"
            elif bg is None and color in _WHITE:
                reason = "white text on the default white page"
        parent_reason, parent_color, parent_bg = self._current()
        self.stack.append(_Frame(tag, parent_reason or reason, color or parent_color, background or parent_bg))
        self._open[tag] = self._open.get(tag, 0) + 1

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        tag = tag.lower()
        if tag in SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
            self._style_buf = None
        elif tag not in VOID and self.stack and self.stack[-1].tag == tag:
            self._open[self.stack.pop().tag] -= 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag not in INLINE:
            self._break = True
        if tag in SKIP:
            self._skip_depth = max(0, self._skip_depth - 1)
            if tag == "style" and self._style_buf is not None:
                self.sheet.update(parse_stylesheet("".join(self._style_buf)))
                self._style_buf = None
            return
        if not self._open.get(tag):
            return  # stray end tag: nothing to close
        while self.stack:
            frame = self.stack.pop()
            self._open[frame.tag] -= 1
            if frame.tag == tag:
                return

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            if self._style_buf is not None:
                self._style_buf.append(data)
            return
        reason, _, _ = self._current()
        self._emit(data, reason)

    def handle_comment(self, data: str) -> None:
        if data.strip():
            line = self._line()
            self.segments.append(Segment(data, f"line {line}", line, hidden=True, reason="HTML comment"))


def extract_html(text: str, line_offset: int = 0) -> tuple[list[Segment], list[Link]]:
    parser = VisibilityParser(line_offset=line_offset)
    parser.feed(text)
    parser.close()
    return parser.segments, parser.links
