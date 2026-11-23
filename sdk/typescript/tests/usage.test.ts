import { describe, expect, it } from "vitest";
import { InvalidResponseError, ValidationError } from "../src/index.js";
import { at, clientFor, queryOf, ok } from "./helpers.js";

const FROM = new Date("2026-11-01T00:00:00Z");
const TO = new Date("2026-12-01T00:00:00Z");
const PERIOD = { from: FROM, to: TO };

const TOTALS = [
  { dimension: "vcpu", unit: "vcpu_hours", total: 12.5 },
  { dimension: "memory_mib", unit: "mib_hours", total: 2048 },
];

function group(value: string | null, key = "sandbox"): Record<string, unknown> {
  return { group_key: key, group_value: value, totals: TOTALS };
}

async function collect<T>(items: AsyncIterable<T>): Promise<T[]> {
  const out: T[] = [];
  for await (const item of items) out.push(item);
  return out;
}

describe("usage.get", () => {
  it("returns the org totals for the period", async () => {
    const { client, requests } = clientFor([ok(TOTALS)]);

    const report = await client.usage.get(PERIOD);

    const url = new URL(at(requests, 0).url);
    expect(url.pathname).toBe("/v1/org/usage");
    expect(queryOf(at(requests, 0))).toEqual({
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-12-01T00:00:00.000Z",
    });
    expect(report.totals).toEqual([
      { dimension: "vcpu", unit: "vcpu_hours", total: 12.5 },
      { dimension: "memory_mib", unit: "mib_hours", total: 2048 },
    ]);
    expect(report.groups).toEqual([]);
    expect(report.nextCursor).toBeNull();
  });

  it("returns a page of groups with the cursor of the next one", async () => {
    const withName = { ...group("sbx_1"), name: "demo", labels: { team: "a" } };
    const { client, requests } = clientFor([ok([withName, group(null, "label:team")], "n1")]);

    const report = await client.usage.get({
      ...PERIOD,
      groupBy: "sandbox",
      cursor: "c0",
      limit: 20,
    });

    const params = new URL(at(requests, 0).url).searchParams;
    expect(params.get("group_by")).toBe("sandbox");
    expect(params.get("cursor")).toBe("c0");
    expect(params.get("limit")).toBe("20");
    expect(report.totals).toEqual([]);
    expect(report.nextCursor).toBe("n1");
    expect(report.groups[0]).toMatchObject({
      groupKey: "sandbox",
      groupValue: "sbx_1",
      name: "demo",
      labels: { team: "a" },
    });
    expect(report.groups[0]?.totals).toHaveLength(2);
    expect(report.groups[1]).toMatchObject({ groupKey: "label:team", groupValue: null });
    expect(report.groups[1]?.name).toBeNull();
    expect(report.groups[1]?.labels).toBeNull();
  });

  it("accepts a label group key", async () => {
    const { client, requests } = clientFor([ok([], null)]);

    await client.usage.get({ ...PERIOD, groupBy: "label:team" });

    expect(new URL(at(requests, 0).url).searchParams.get("group_by")).toBe("label:team");
  });

  it("refuses bad arguments before sending", async () => {
    const { client, requests } = clientFor([]);
    const bad = [
      client.usage.get({ from: FROM } as never),
      client.usage.get({ to: TO } as never),
      client.usage.get({ from: new Date("x"), to: TO }),
      client.usage.get({ ...PERIOD, groupBy: "tenant" }),
      client.usage.get({ ...PERIOD, groupBy: "label:" }),
      client.usage.get({ ...PERIOD, cursor: "c" }),
      client.usage.get({ ...PERIOD, limit: 5 }),
      client.usage.get({ ...PERIOD, groupBy: "sandbox", limit: 0 }),
      client.usage.get({ ...PERIOD, groupBy: "sandbox", limit: 101 }),
      client.usage.get({ ...PERIOD, groupBy: "sandbox", cursor: " " }),
    ];

    for (const call of bad) await expect(call).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("rejects a total that is not a number", async () => {
    const { client } = clientFor([ok([{ dimension: "vcpu", unit: "u", total: "9" }])]);

    await expect(client.usage.get(PERIOD)).rejects.toBeInstanceOf(InvalidResponseError);
  });
});

describe("usage.groupsAll", () => {
  it("walks the pages with the same period and group, passing the cursor back", async () => {
    const { client, requests } = clientFor([
      ok([group("sbx_1"), group("sbx_2")], "c1"),
      ok([group("sbx_3")], null),
    ]);

    const all = client.usage.groupsAll({ ...PERIOD, groupBy: "sandbox", limit: 2 });
    const groups = await collect(all);

    expect(groups.map((g) => g.groupValue)).toEqual(["sbx_1", "sbx_2", "sbx_3"]);
    const [first, second] = requests.map((r) => new URL(r.url).searchParams);
    expect(first?.get("cursor")).toBeNull();
    expect(second?.get("cursor")).toBe("c1");
    expect(second?.get("from")).toBe("2026-11-01T00:00:00.000Z");
    expect(second?.get("group_by")).toBe("sandbox");
    expect(second?.get("limit")).toBe("2");
  });

  it("needs a group_by and an explicit period, and sends nothing without them", async () => {
    const { client, requests } = clientFor([]);

    await expect(collect(client.usage.groupsAll(PERIOD as never))).rejects.toBeInstanceOf(
      ValidationError,
    );
    await expect(
      collect(client.usage.groupsAll({ groupBy: "sandbox" } as never)),
    ).rejects.toBeInstanceOf(ValidationError);
    expect(requests).toHaveLength(0);
  });

  it("refuses a repeated cursor instead of looping", async () => {
    const { client, requests } = clientFor([
      ok([group("a")], "c1"),
      ok([group("b")], "c1"),
      ok([group("c")], "c1"),
    ]);

    await expect(
      collect(client.usage.groupsAll({ ...PERIOD, groupBy: "sandbox" })),
    ).rejects.toBeInstanceOf(InvalidResponseError);
    expect(requests).toHaveLength(2);
  });
});
