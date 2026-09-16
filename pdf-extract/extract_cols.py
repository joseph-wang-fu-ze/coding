# -*- coding: utf-8 -*-
"""
按栏抽取 PDF 文本。

为什么需要它：学术论文是两栏排版，直接 extract_text() 会把左右栏逐行交错拼接，
读出来是乱的（工作区里已有的 _pdf_raw.txt 就是这么来的）。
这里按页面中线切两半分别抽取，再按"左栏 → 右栏"的顺序拼回去。

用法：
    python extract_cols.py <pdf路径> <输出txt路径> [栏分割比例，默认 0.5]
"""
import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

import pdfplumber


def extract(pdf_path, out_path, gutter_ratio=0.5):
    chunks = []
    with pdfplumber.open(pdf_path) as pdf:
        total = len(pdf.pages)
        for i, page in enumerate(pdf.pages):
            w, h = page.width, page.height
            mid = w * gutter_ratio
            left = page.crop((0, 0, mid, h)).extract_text() or ''
            right = page.crop((mid, 0, w, h)).extract_text() or ''
            chunks.append("===== PAGE %d =====" % (i + 1))
            chunks.append("[LEFT]")
            chunks.append(left)
            chunks.append("[RIGHT]")
            chunks.append(right)
    text = "\n".join(chunks)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(text)
    print("pages=%d  chars=%d  -> %s" % (total, len(text), out_path))


if __name__ == '__main__':
    pdf_path = sys.argv[1]
    out_path = sys.argv[2]
    ratio = float(sys.argv[3]) if len(sys.argv) > 3 else 0.5
    extract(pdf_path, out_path, ratio)
