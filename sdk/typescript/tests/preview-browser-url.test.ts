import { describe, expect, it } from "vitest";
import { InvalidResponseError } from "../src/index.js";
import { clientFor } from "./helpers.js";

const URL_WITH_QUERY = "https://3000-sbx_1.preview.sf.test/?sandfort_preview_token=pv_abc";
const BROWSER_URL =
  "https://3000-sbx_1.preview.sf.test/__sandfort/preview#sandfort_preview_token=pv_abc";
const PREVIEW = {
  token: "pv_abc",
  url: URL_WITH_QUERY,
  port: 3000,
  expires_at: "2026-11-11T10:00:00+00:00",
};

function created(data: unknown): Response {
  return new Response(JSON.stringify({ success: true, data }), {
    status: 201,
    headers: { "content-type": "application/json" },
  });
}

describe("mintPreviewToken browser_url", () => {
  it("maps browser_url to an enumerable browserUrl next to the unchanged url", async () => {
    const { client } = clientFor([created({ ...PREVIEW, browser_url: BROWSER_URL })]);

    const preview = await client.mintPreviewToken("sbx_1", { port: 3000 });

    expect(preview.browserUrl).toBe(BROWSER_URL);
    expect(preview.url).toBe(URL_WITH_QUERY);
    expect(Object.keys(preview)).toContain("browserUrl");
    expect(Object.keys(preview)).not.toContain("token");
    expect(preview.token).toBe("pv_abc");
  });

  it.each([[PREVIEW], [{ ...PREVIEW, browser_url: null }]])(
    "leaves browserUrl out when the server sends none or null",
    async (answer) => {
      const { client } = clientFor([created(answer)]);

      const preview = await client.mintPreviewToken("sbx_1", { port: 3000 });

      expect("browserUrl" in preview).toBe(false);
      expect(preview.url).toBe(URL_WITH_QUERY);
    },
  );

  it("rejects a browser_url that is not a string", async () => {
    const { client } = clientFor([created({ ...PREVIEW, browser_url: 5 })]);

    await expect(client.mintPreviewToken("sbx_1", { port: 3000 })).rejects.toBeInstanceOf(
      InvalidResponseError,
    );
  });
});
