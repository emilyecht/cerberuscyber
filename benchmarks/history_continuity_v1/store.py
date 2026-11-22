"""Linux research fixture. The controller owns the anchor directory and all writers."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import tempfile

from cerberus.state import ReplayDetected, SQLiteStateStore, StateUnavailable


def sync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(path, data):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as out:
        stage = Path(out.name)
        try:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
            os.replace(stage, path)
            sync_dir(path.parent)
        finally:
            stage.unlink(missing_ok=True)


class AnchoredHistory:
    def __init__(self, live, anchor_dir, namespace):
        self.live = Path(live)
        self.anchor = Path(anchor_dir) / "checkpoint"
        self.namespace = namespace

    @contextmanager
    def locked(self):
        try:
            fd = os.open(self.anchor.parent, os.O_DIRECTORY)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                yield
            finally:
                os.close(fd)
        except (ReplayDetected, StateUnavailable):
            raise
        except (sqlite3.Error, OSError, ValueError, KeyError, TypeError) as exc:
            raise StateUnavailable("history continuity unavailable") from exc

    def checkpoint(self, image, epoch):
        info = image.stat()
        return dict(namespace=self.namespace, epoch=epoch, device=info.st_dev,
                    inode=info.st_ino, digest=hashlib.sha256(image.read_bytes()).hexdigest())

    def provision(self):
        # Trusted first enrollment only. A unique database header binds this lineage.
        with self.locked():
            if self.live.exists() or self.anchor.exists():
                raise StateUnavailable("already enrolled or incomplete provisioning")
            SQLiteStateStore(self.live, namespace=self.namespace, create=True)
            db = sqlite3.connect(self.live)
            try:
                with db:
                    db.execute("CREATE TABLE lineage (identity TEXT NOT NULL)")
                    db.execute("INSERT INTO lineage VALUES (?)", (secrets.token_hex(32),))
            finally:
                db.close()
            sync_dir(self.live.parent)
            publish(self.anchor, json.dumps(self.checkpoint(self.live, 0)).encode())

    def _update(self, operation, backup=None):
        with self.locked():
            record = json.loads(self.anchor.read_bytes())
            if (not isinstance(record, dict)
                    or set(record) != {"namespace", "epoch", "device", "inode", "digest"}
                    or any(type(record[key]) is not int or record[key] < 0 for key in ("device", "inode"))):
                raise StateUnavailable("malformed checkpoint")
            epoch = record["epoch"]
            if type(epoch) is not int or epoch < 0 or record["namespace"] != self.namespace:
                raise StateUnavailable("wrong epoch or namespace")
            with tempfile.TemporaryDirectory(dir=self.live.parent) as directory:
                stage = Path(directory) / "history.db"
                source = self.live if backup is None else Path(backup)
                if source.is_symlink() or not source.is_file():
                    raise StateUnavailable("missing or invalid history")
                if backup is None and self.checkpoint(source, epoch) != record:
                    raise StateUnavailable("live history differs from checkpoint")
                stage.write_bytes(source.read_bytes())
                if self.checkpoint(stage, epoch)["digest"] != record["digest"]:
                    raise StateUnavailable("snapshot differs from checkpoint")
                store = SQLiteStateStore(stage, namespace=self.namespace)
                result = operation(store)
                if result is False:
                    return False
                with stage.open("rb") as image:
                    os.fsync(image.fileno())
                # Commit the witness first. Interruption now requires a matching
                # recovery image. Never issue a successful result before publication.
                publish(self.anchor, json.dumps(self.checkpoint(stage, epoch + 1)).encode())
                self._install(stage)
                return result

    def _install(self, stage):
        os.replace(stage, self.live)
        sync_dir(self.live.parent)

    def claim(self, key, digest):
        return self._update(lambda store: store.claim(key, digest))

    def consume(self, token, key, digest):
        return self._update(lambda store: store.consume(token, key, digest))

    def recover(self, backup):
        # Trusted operator entry point. Authenticate exact bytes against the witness.
        self._update(lambda store: None, backup)
