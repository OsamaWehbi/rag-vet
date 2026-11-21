from make_demo_corpus import build_pdf, text_op

from rag_vet.extract.docx import extract_docx
from rag_vet.extract.pdf import extract_pdf


def pdf_hidden(tmp_path, pages, **kwargs) -> dict[str, str]:
    path = tmp_path / "t.pdf"
    path.write_bytes(build_pdf(pages, **kwargs))
    return {s.text.strip(): s.reason for s in extract_pdf(str(path)) if s.hidden and s.text.strip()}


def test_pdf_hiding_techniques(tmp_path):
    hidden = pdf_hidden(
        tmp_path,
        [
            [
                text_op("plain visible text on the page", 72, 700),
                text_op("white words", 72, 680, fill="1 1 1 rg"),
                text_op("gray white words", 72, 670, fill="1 g"),
                text_op("cmyk white words", 72, 660, fill="0 0 0 0 k"),
                text_op("never painted", 72, 650, mode=3),
                text_op("very small print", 72, 640, 0.5),
                text_op("below the page", 72, -400),
                text_op("right of the page", 900, 400),
            ]
        ],
    )
    assert hidden == {
        "white words": "white text",
        "gray white words": "white text",
        "cmyk white words": "white text",
        "never painted": "invisible text (render mode 3)",
        "very small print": "tiny font (0.50 pt)",
        "below the page": "outside the page",
        "right of the page": "outside the page",
    }


def test_pdf_graphics_state_is_restored(tmp_path):
    # Each text_op is wrapped in q/Q, so white fill must not leak into the next line.
    hidden = pdf_hidden(tmp_path, [[text_op("white", 72, 700, fill="1 1 1 rg"), text_op("black again", 72, 680)]])
    assert hidden == {"white": "white text"}


def test_pdf_dark_text_is_visible(tmp_path):
    assert pdf_hidden(tmp_path, [[text_op("dark grey", 72, 700, fill="0.2 0.2 0.2 rg")]]) == {}


def test_pdf_ocr_layer_is_labelled(tmp_path):
    hidden = pdf_hidden(tmp_path, [[text_op("scanned page text recognised by OCR", 72, 700, mode=3)]])
    assert hidden == {"scanned page text recognised by OCR": "invisible text layer (probably OCR)"}


def test_pdf_metadata_and_annotations(tmp_path):
    hidden = pdf_hidden(
        tmp_path,
        [[text_op("body", 72, 700)]],
        info={"Title": "A title", "Producer": "ignored producer"},
        annotations=["note text"],
    )
    assert hidden == {"A title": "PDF metadata", "note text": "annotation (Text)"}


def test_pdf_pages_are_located(tmp_path):
    path = tmp_path / "p.pdf"
    path.write_bytes(build_pdf([[text_op("one", 72, 700)], [text_op("two", 72, 700, fill="1 1 1 rg")]]))
    hidden = [s for s in extract_pdf(str(path)) if s.hidden]
    assert [(s.text.strip(), s.location) for s in hidden] == [("two", "page 2")]


def make_docx(path, build):
    import docx

    d = docx.Document()
    build(d)
    d.save(path)
    return path


def docx_hidden(path) -> dict[str, str]:
    segments, _ = extract_docx(str(path))
    return {
        s.text.strip(): s.reason for s in segments if s.hidden and s.text.strip() and s.reason != "document properties"
    }


def test_docx_hidden_runs(tmp_path):
    from docx.enum.text import WD_COLOR_INDEX
    from docx.shared import Pt, RGBColor

    def build(d):
        p = d.add_paragraph("visible ")
        p.add_run("vanished").font.hidden = True
        r = d.add_paragraph().add_run("white run")
        r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        highlighted = d.add_paragraph().add_run("white on highlight")
        highlighted.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        highlighted.font.highlight_color = WD_COLOR_INDEX.BLACK
        d.add_paragraph().add_run("tiny run").font.size = Pt(1)
        d.add_paragraph().add_run("normal size").font.size = Pt(11)

    hidden = docx_hidden(make_docx(tmp_path / "d.docx", build))
    assert hidden == {
        "vanished": "hidden text (Word hidden font)",
        "white run": "white text",
        "tiny run": "tiny font (1 pt)",
    }


def test_docx_hidden_style(tmp_path):
    from docx.enum.style import WD_STYLE_TYPE

    def build(d):
        style = d.styles.add_style("Secret", WD_STYLE_TYPE.PARAGRAPH)
        style.font.hidden = True
        d.add_paragraph("styled hidden", style="Secret")

    assert docx_hidden(make_docx(tmp_path / "s.docx", build)) == {"styled hidden": "hidden text (Word hidden font)"}


def test_docx_tables_properties_and_links(tmp_path):
    def build(d):
        d.core_properties.subject = "subject text"
        cell = d.add_table(rows=1, cols=1).cell(0, 0)
        cell.paragraphs[0].add_run("in a table").font.hidden = True
        part = d.part
        part.relate_to(
            "https://link.example/x",
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink",
            is_external=True,
        )

    path = make_docx(tmp_path / "t.docx", build)
    segments, links = extract_docx(str(path))
    hidden = {s.text.strip(): s.reason for s in segments if s.hidden and s.text.strip()}
    assert hidden["subject text"] == "document properties"
    assert hidden["in a table"] == "hidden text (Word hidden font)"
    assert [link.url for link in links] == ["https://link.example/x"]
