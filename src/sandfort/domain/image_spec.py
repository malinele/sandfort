"""FROZEN: declarative image spec and its canonical content hash."""

import hashlib
import json

from pydantic import BaseModel, ConfigDict, Field


class ImageFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    destination: str
    content: str


class ImageSpec(BaseModel):
    """What to build on top of ``base_image``; order of list entries never matters."""

    model_config = ConfigDict(frozen=True)

    base_image: str
    pip_packages: list[str] = Field(default_factory=list)
    apt_packages: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    workdir: str | None = None
    files: list[ImageFile] = Field(default_factory=list)

    @property
    def spec_hash(self) -> str:
        """sha256 hex of a canonical, order-independent JSON form of the spec."""
        canonical = {
            "base_image": self.base_image,
            "pip_packages": sorted(self.pip_packages),
            "apt_packages": sorted(self.apt_packages),
            "env": self.env,
            "workdir": self.workdir,
            "files": sorted(
                ({"destination": f.destination, "content": f.content} for f in self.files),
                key=lambda entry: (entry["destination"], entry["content"]),
            ),
        }
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
