"""Show the offline structural history boundary with synthetic files."""

import json
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptalis.manifest.canonical import digest_manifest_json


def _inspect(label: str, paths: list[Path], expected_exit: int) -> dict[str, object]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "cryptalis",
            "manifest",
            "inspect-history",
            *(str(path) for path in paths),
            "--json",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    if result.returncode != expected_exit:
        raise RuntimeError(f"The {label} case returned an unexpected exit code.")
    if expected_exit == 0:
        if result.stderr:
            raise RuntimeError("A successful inspection wrote an error.")
        output = json.loads(result.stdout)
        if (
            output["scope"] != "manifest_history"
            or output["authenticated"] is not False
        ):
            raise RuntimeError("The inspection scope is incorrect.")
        print(f"  ACCEPTED  {label} (exit 0, authenticated=false)")
    else:
        if result.stdout:
            raise RuntimeError("A failed inspection wrote success output.")
        output = json.loads(result.stderr)["error"]
        if (output["family"], output["code"], output["stage"]) != (
            "Manifest",
            "Invalid",
            "history",
        ):
            raise RuntimeError("The inspection failure category is incorrect.")
        print(f"  REJECTED  {label} (exit 2, Manifest.Invalid)")
    return output


def main() -> None:
    print("CRYPTALIS: offline manifest history inspection")
    print("Synthetic inputs. Structural consistency only. No policy activation.\n")
    with TemporaryDirectory(prefix="cryptalis-history-demo-") as directory:
        paths = [
            Path(directory) / f"revision-{revision}.json" for revision in (0, 1, 4)
        ]
        examples = Path(__file__).parent / "manifests"
        paths[0].write_bytes((examples / "genesis.json").read_bytes())
        paths[1].write_bytes((examples / "successor.json").read_bytes())
        document = json.loads(paths[1].read_bytes())
        document.update(
            revision=4, parent_digest=digest_manifest_json(paths[1].read_bytes())
        )
        paths[2].write_text(json.dumps(document), encoding="utf-8")

        head = _inspect("complete chain: revision 0 -> 1 -> 4", paths, 0)
        if head["document_count"] != 3 or head["revision"] != 4:
            raise RuntimeError("The inspection returned an incorrect history head.")
        print(f"            head digest: {head['digest']}")

        original = paths[1].read_bytes()
        paths[1].write_text(
            json.dumps(json.loads(original), indent=4), encoding="utf-8"
        )
        formatted = _inspect("whitespace change: same canonical content", paths, 0)
        if formatted["digest"] != head["digest"]:
            raise RuntimeError("A presentation change altered the content digest.")

        changed = json.loads(original)
        changed["description"] = "synthetic changed policy"
        paths[1].write_text(json.dumps(changed), encoding="utf-8")
        _inspect("changed ancestor: broken digest link", paths, 2)
        paths[1].write_bytes(original)
        _inspect("missing middle ancestor", [paths[0], paths[2]], 2)
        _inspect("reversed history", list(reversed(paths)), 2)

        # Recomputed links show why structural consistency supplies no authority.
        previous = None
        for path in paths:
            changed = json.loads(path.read_bytes())
            changed.update(
                description="synthetic replacement policy", parent_digest=previous
            )
            raw = json.dumps(changed).encode("utf-8")
            path.write_bytes(raw)
            previous = digest_manifest_json(raw)
        _inspect(
            "consistent replacement chain: authentication remains absent", paths, 0
        )
    print("\nAll six expected outcomes passed. Temporary files were removed.")
    print(
        "A digest link detects inconsistency. It does not prove who authorized the history."
    )


if __name__ == "__main__":
    main()
