from rag_vet.extract.markdown import extract_markdown


def test_code_blocks_are_not_markup():
    md = 'Example:\n\n```html\n<div style="display:none">x y z</div>\n```\n\nand `<span hidden>inline</span>`.'
    segments, _ = extract_markdown(md)
    assert not [s for s in segments if s.hidden]
    text = "".join(s.text for s in segments)
    assert '<div style="display:none">' in text
    assert "<span hidden>inline</span>" in text


def test_raw_html_comments_and_spans_are_hidden():
    md = 'Visible.\n\n<!-- hidden comment -->\n\n<span style="display:none">hidden span</span>\n'
    segments, _ = extract_markdown(md)
    hidden = {s.text.strip(): (s.reason, s.line) for s in segments if s.hidden}
    assert hidden == {"hidden comment": ("HTML comment", 3), "hidden span": ("display:none", 5)}


def test_links_images_titles_and_reference_definitions():
    md = '[a](https://a.example "tip")\n![logo text](https://b.example/l.png)\n\n[ref]: https://c.example/r "ref title"\n'
    segments, links = extract_markdown(md)
    assert {(link.url, link.image) for link in links} == {
        ("https://a.example", False),
        ("https://b.example/l.png", True),
        ("https://c.example/r", False),
    }
    reasons = {s.reason for s in segments if s.hidden}
    assert reasons == {"link title", "image alt text", "link reference definition"}
