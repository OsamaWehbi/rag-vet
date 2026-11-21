import pytest

from rag_vet.extract.html import extract_html, hidden_reason, parse_declarations


def hidden_texts(html: str) -> dict[str, str]:
    segments, _ = extract_html(html)
    return {s.text.strip(): s.reason for s in segments if s.hidden and s.text.strip()}


def visible_text(html: str) -> str:
    segments, _ = extract_html(html)
    return " ".join(s.text.strip() for s in segments if not s.hidden and s.text.strip())


@pytest.mark.parametrize(
    ("style", "expected"),
    [
        ("display:none", "display:none"),
        ("display: none !important", "display:none"),
        ("visibility:hidden", "visibility:hidden"),
        ("opacity:0", "opacity:0"),
        ("opacity: 0.0", "opacity:0"),
        ("font-size:0", "font-size:0"),
        ("font-size:1px", "font-size:1px"),
        ("position:absolute; left:-9999px", "positioned off-screen (left:-9999px)"),
        ("text-indent:-10000px", "positioned off-screen (text-indent:-10000px)"),
        ("color:transparent", "transparent text"),
        ("color:#000; background-color:#000", "text colour matches background (#000)"),
        ("height:0; overflow:hidden", "height:0 with overflow:hidden"),
    ],
)
def test_hidden_styles(style, expected):
    assert hidden_reason(parse_declarations(style)) == expected


@pytest.mark.parametrize("style", ["display:block", "opacity:0.9", "font-size:14px", "left:10px", "color:#333"])
def test_visible_styles(style):
    assert hidden_reason(parse_declarations(style)) is None


def test_inline_style_and_nesting():
    html = '<p>Shown <span style="display:none">secret words here <b>still hidden</b></span> shown again</p>'
    hidden = hidden_texts(html)
    assert "secret words here still hidden" in hidden
    visible = visible_text(html)
    assert "Shown" in visible
    assert "shown again" in visible
    assert "secret" not in visible


def test_white_text_on_default_page_and_on_dark_background():
    assert hidden_texts('<p style="color:white">invisible on white</p>') == {
        "invisible on white": "white text on the default white page"
    }
    # White text on a dark background is normal.
    assert hidden_texts('<div style="background-color:#111"><p style="color:#fff">readable</p></div>') == {}


def test_stylesheet_selectors():
    html = """<style>.x, #y { display:none } p.z { display:none } div > span { display:none }</style>
    <div class="a x">by class</div><div id="y">by id</div><p class="z">compound ignored</p>"""
    hidden = hidden_texts(html)
    assert hidden == {"by class\nby id": "display:none"}


def test_hidden_attribute_template_and_comments():
    hidden = hidden_texts("<div hidden>attr</div><template>tpl</template><!-- a comment -->")
    assert hidden == {"attr": "hidden attribute", "tpl": "<template> element", "a comment": "HTML comment"}


def test_scripts_and_styles_are_not_text():
    html = "<script>var ignore_previous_instructions = 1;</script><style>p{color:red}</style><p>body</p>"
    segments, _ = extract_html(html)
    assert "".join(s.text for s in segments).strip() == "body"


def test_attributes_and_meta_are_hidden_segments():
    html = '<meta name="description" content="meta text"><img src="a.png" alt="alt words"><a title="tip">x</a>'
    hidden = hidden_texts(html)
    assert hidden == {"meta text": "meta tag", "alt words": "alt text", "tip": "title attribute"}


def test_links_and_images_collected_with_lines():
    _, links = extract_html('<a href="https://a.example/x">a</a>\n<img src="https://b.example/i.png">')
    assert [(link.url, link.image, link.line) for link in links] == [
        ("https://a.example/x", False, 1),
        ("https://b.example/i.png", True, 2),
    ]


def test_unclosed_and_stray_tags_do_not_leak_hidden_state():
    html = '<div style="display:none"><p>hidden</div><p>visible</p></span></p>'
    assert hidden_texts(html) == {"hidden": "display:none"}
    assert "visible" in visible_text(html)


def test_line_numbers():
    segments, _ = extract_html("<p>one</p>\n\n<p style='display:none'>three</p>")
    hidden = [s for s in segments if s.hidden]
    assert hidden[0].line == 3


def test_deep_nesting_is_bounded():
    html = "<div>" * 20000 + '<span style="display:none">deep hidden text</span>' + "</div>" * 20000
    assert hidden_texts(html) == {"deep hidden text": "display:none"}


def test_stray_end_tags_and_self_closing_script_are_harmless():
    html = "</div>" * 20000 + "<script/><p style='display:none'>after a self-closing script tag</p>"
    assert hidden_texts(html) == {"after a self-closing script tag": "display:none"}


def test_presentational_colour_attributes():
    assert hidden_texts('<font color="#FFFFFF">old school white</font>') == {
        "old school white": "white text on the default white page"
    }
    assert hidden_texts('<table bgcolor="black"><tr><td><font color="white">fine</font></td></tr></table>') == {}
