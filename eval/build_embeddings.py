"""Chunk the protected prompt and save an embedding for each chunk (issue #12).

Examples (run from the repo root):
  python3 eval/build_embeddings.py --dry-run            # chunk only, show counts, call nothing
  python3 eval/build_embeddings.py --mode local         # fake embeddings, no AWS, pipeline test only
  python3 eval/build_embeddings.py --mode local-model   # real embeddings on this machine, no AWS (pip install sentence-transformers)
  python3 eval/build_embeddings.py --mode bedrock       # real embeddings, needs AWS access, costs a tiny amount

Outputs:
  eval/data/prompt_chunks.json          the chunks (small text file, fine to commit)
  eval/data/embeddings/<model>.npz      the vectors (generated: ignored by git, rebuild any time)
"""
import argparse
import json
from pathlib import Path

import numpy as np

from chunk_prompt import chunk_prompt, prompt_sha256
from embedder import DEFAULT_REGION, embed_texts, embeddings_filename, model_name

DATA = Path(__file__).parent / "data"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--prompt", default=str(DATA / "placeholder_prompt.txt"), help="protected prompt text file")
    parser.add_argument("--mode", choices=["local", "local-model", "bedrock"], default="local")
    parser.add_argument("--region", default=DEFAULT_REGION)
    parser.add_argument("--dry-run", action="store_true", help="chunk and report only; make no embedding calls")
    args = parser.parse_args()

    text = Path(args.prompt).read_text(encoding="utf-8")
    chunks = chunk_prompt(text)
    chars = sum(len(c["text"]) for c in chunks)
    print(f"{len(chunks)} chunks, {chars} characters (roughly {chars // 4} tokens)")

    (DATA / "prompt_chunks.json").write_text(
        json.dumps({"prompt_sha256": prompt_sha256(text), "chunks": chunks}, indent=2) + "\n", encoding="utf-8"
    )
    print("wrote eval/data/prompt_chunks.json")
    if args.dry_run:
        print("dry run: no embeddings made")
        return

    vectors = embed_texts([c["text"] for c in chunks], mode=args.mode, region=args.region)
    out_dir = DATA / "embeddings"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / embeddings_filename(args.mode)
    np.savez(
        out_path,
        vectors=vectors,
        ids=np.array([c["id"] for c in chunks]),
        model=np.array(model_name(args.mode)),
        prompt_sha256=np.array(prompt_sha256(text)),
    )
    print(f"wrote {out_path.relative_to(DATA.parent.parent)}  shape={vectors.shape}  model={model_name(args.mode)}")
    if args.mode == "local":
        print("NOTE: local mode is a fake embedder for testing the pipeline. Do not report results from it.")
    if args.mode == "local-model":
        print(f"NOTE: vectors made by the local model {model_name(args.mode)}. Label every result with that model name.")


if __name__ == "__main__":
    main()
