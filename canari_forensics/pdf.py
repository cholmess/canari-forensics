from __future__ import annotations

from pathlib import Path


class SimplePDF:
    """Very small PDF writer for text-only reports (no external deps)."""

    def write(self, path: str | Path, lines: list[str]) -> None:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)

        y = 790
        commands = ["BT", "/F1 10 Tf", "72 800 Td"]
        for line in lines:
            safe = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append(f"1 0 0 1 72 {y} Tm ({safe}) Tj")
            y -= 14
            if y < 40:
                break
        commands.append("ET")
        content_stream = "\n".join(commands).encode("latin-1", errors="replace")

        objects: list[bytes] = []
        objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")
        objects.append(b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n")
        objects.append(
            b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n"
        )
        objects.append(b"4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n")
        objects.append(
            b"5 0 obj << /Length "
            + str(len(content_stream)).encode("ascii")
            + b" >> stream\n"
            + content_stream
            + b"\nendstream endobj\n"
        )

        header = b"%PDF-1.4\n"
        offsets = []
        body = bytearray(header)
        for obj in objects:
            offsets.append(len(body))
            body.extend(obj)

        xref_start = len(body)
        body.extend(f"xref\n0 {len(objects)+1}\n".encode("ascii"))
        body.extend(b"0000000000 65535 f \n")
        for off in offsets:
            body.extend(f"{off:010d} 00000 n \n".encode("ascii"))

        body.extend(
            (
                "trailer << /Size "
                + str(len(objects) + 1)
                + " /Root 1 0 R >>\nstartxref\n"
                + str(xref_start)
                + "\n%%EOF\n"
            ).encode("ascii")
        )

        out.write_bytes(bytes(body))
