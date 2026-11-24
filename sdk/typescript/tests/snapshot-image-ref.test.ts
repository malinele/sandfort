import { describe, expect, it } from "vitest";
import { Image, InvalidResponseError } from "../src/index.js";
import { clientFor, ok } from "./helpers.js";

const SNAPSHOT = {
  id: "snap_1",
  name: "s",
  state: "ready",
  image_ref: "sandfort/snap_1:latest",
  layer_count: 1,
  created_at: "2026-11-01T09:00:00+00:00",
};

/** A label-scoped key gets `image_ref: null` (the operator's registry path is withheld). */
const HIDDEN = { ...SNAPSHOT, image_ref: null };

describe("snapshot imageRef with a label-scoped key", () => {
  it("maps a null image_ref to imageRef null on get", async () => {
    const { client } = clientFor([ok(HIDDEN)]);

    expect((await client.getSnapshot("snap_1")).imageRef).toBeNull();
  });

  it("keeps the string for an org-wide key", async () => {
    const { client } = clientFor([ok(SNAPSHOT)]);

    expect((await client.getSnapshot("snap_1")).imageRef).toBe("sandfort/snap_1:latest");
  });

  it("maps null on list, create, register and build too", async () => {
    const { client } = clientFor([
      ok([HIDDEN], null),
      ok(HIDDEN),
      ok(HIDDEN),
      ok({ ...HIDDEN, spec_hash: "h", reused: false }),
    ]);

    const page = await client.listSnapshots();
    const created = await client.createSnapshot("sbx_1", "s");
    const registered = await client.registerSnapshot("busybox");
    const built = await client.buildSnapshot(Image.debianSlim());

    expect(page.items.map((s) => s.imageRef)).toEqual([null]);
    expect([created.imageRef, registered.imageRef, built.imageRef]).toEqual([null, null, null]);
  });

  it("still rejects an image_ref that is missing or not a string", async () => {
    const { image_ref: _dropped, ...missing } = SNAPSHOT;
    const { client } = clientFor([ok(missing), ok({ ...SNAPSHOT, image_ref: 7 })]);

    await expect(client.getSnapshot("snap_1")).rejects.toBeInstanceOf(InvalidResponseError);
    await expect(client.getSnapshot("snap_1")).rejects.toBeInstanceOf(InvalidResponseError);
  });
});
