#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import tarfile
import tempfile
import time
from pathlib import Path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def add_file(tar: tarfile.TarFile, src: Path, name: str, mode: int):
    info = tar.gettarinfo(str(src), arcname=name)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    with src.open("rb") as f:
        tar.addfile(info, f)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--agents-dir")
    args = parser.parse_args()

    binary = Path(args.binary).resolve()
    out = Path(args.out).resolve()
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        layer = work / "layer.tar"
        with tarfile.open(layer, "w") as lt:
            add_file(lt, binary, "accessgate", 0o755)
            if args.agents_dir:
                agents_dir = Path(args.agents_dir).resolve()
                for agent in sorted(agents_dir.glob("accessgate-agent-linux-*")):
                    add_file(lt, agent, "agents/" + agent.name, 0o755)

        diff_id = "sha256:" + sha256_file(layer)
        config = {
            "created": created,
            "architecture": "arm64",
            "os": "linux",
            "config": {
                "Entrypoint": ["/accessgate"],
                "Env": ["ACCESSGATE_ADDR=:8080", "ACCESSGATE_DATA_DIR=/var/lib/accessgate"],
                "WorkingDir": "/",
                "ExposedPorts": {"8080/tcp": {}},
            },
            "rootfs": {"type": "layers", "diff_ids": [diff_id]},
            "history": [{"created": created, "created_by": "accessgate d2 build"}],
        }
        config_bytes = json.dumps(config, separators=(",", ":")).encode()
        config_name = hashlib.sha256(config_bytes).hexdigest() + ".json"
        (work / config_name).write_bytes(config_bytes)

        layer_name = "accessgate-layer/layer.tar"
        manifest = [{
            "Config": config_name,
            "RepoTags": [args.image],
            "Layers": [layer_name],
        }]
        (work / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        repo, tag = args.image.rsplit(":", 1)
        (work / "repositories").write_text(json.dumps({repo: {tag: config_name[:-5]}}), encoding="utf-8")

        out.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(out, "w") as ot:
            for name in [config_name, "manifest.json", "repositories"]:
                ot.add(work / name, arcname=name)
            layer_dir = work / "accessgate-layer"
            layer_dir.mkdir()
            os.replace(layer, layer_dir / "layer.tar")
            ot.add(layer_dir / "layer.tar", arcname=layer_name)


if __name__ == "__main__":
    main()
