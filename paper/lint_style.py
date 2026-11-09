#!/usr/bin/env python3
"""Counts the sentence patterns a reviewer found overused, so the final text can be checked."""
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "andronet.template.tex").read_text(encoding="utf-8")
body = text[text.index(r"\begin{abstract}"):text.index(r"\begin{credits}")]
body = re.sub(r"(?<!\\)%.*", "", body)  # a comment, never an escaped \% inside a sentence
body = re.sub(r"\\begin\{table\}.*?\\end\{table\}", " ", body, flags=re.S)
body = re.sub(r"\\begin\{figure\}.*?\\end\{figure\}", " ", body, flags=re.S)
sentences = re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", body))

PATTERNS = {
    "X, not Y": r",\s+not\s+\w",
    "not X but Y": r"\bnot\b[^.;]{0,60}\bbut\b",
    "not X; Y": r"\bnot\b[^.]{0,50};",
    "rather than": r"\brather than\b",
    "instead of": r"\binstead of\b",
    "no X but Y": r"\bno\b[^.;]{0,40}\bbut\b",
    "does not ... ; it": r"\b(does|do|is|are) not\b[^.]{0,40};\s*it\b",
    "em dash": r"---|\u2014",
    "not only": r"\bnot only\b",
    "first-person hedge 'we argue'": r"\bwe (would )?argue\b",
}
total_words = len(re.findall(r"[A-Za-z]+", body))
print(f"{len(sentences)} sentences, {total_words} words in body text")
for name, pattern in PATTERNS.items():
    hits = [s for s in sentences if re.search(pattern, s, re.I)]
    print(f"{name:28s} {len(hits)}")
    for h in hits:
        print("    ", h[:150])
openers = {}
for s in sentences:
    words = re.findall(r"[A-Za-z']+", s)
    if len(words) > 2:
        key = " ".join(words[:2]).lower()
        openers[key] = openers.get(key, 0) + 1
print("most repeated sentence openers:", sorted(openers.items(), key=lambda kv: -kv[1])[:8])
abstract = text[text.index(r"\begin{abstract}") + 16:text.index(r"\keywords")]
print("abstract words (approx):", len(re.findall(r"\S+", abstract)))
