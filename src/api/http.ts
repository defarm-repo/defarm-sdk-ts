import { ApiError } from "../errors.js";

export interface HttpAuth {
  bearer?: string;
  apiKey?: string;
}

/**
 * Thin HTTP layer over the gateway. Follows the repointability rule from the partner collection:
 * ONE gateway base (`gw`), with `/auth/*` at the root and everything else under `/v1` — swapping
 * `gw` repoints the whole client (staging vs prod), no host is ever baked into a call site.
 */
export class Http {
  constructor(
    private readonly gw: string,
    private readonly auth: HttpAuth,
    private readonly fetchImpl: typeof fetch = fetch,
  ) {}

  get base(): string {
    return `${this.gw.replace(/\/+$/, "")}/v1`;
  }

  get root(): string {
    return this.gw.replace(/\/+$/, "");
  }

  setBearer(token: string): void {
    this.auth.bearer = token;
  }

  hasApiKey(): boolean {
    return !!this.auth.apiKey;
  }

  async request<T>(
    method: string,
    url: string,
    opts: {
      body?: unknown;
      auth?: "bearer" | "apiKey" | "none";
    } = {},
  ): Promise<T> {
    const headers: Record<string, string> = {};
    if (opts.body !== undefined) headers["Content-Type"] = "application/json";
    const mode = opts.auth ?? "bearer";
    if (mode === "bearer") {
      if (!this.auth.bearer) {
        throw new ApiError(0, "no_bearer", "not logged in — call login() or pass auth.bearer");
      }
      headers["Authorization"] = `Bearer ${this.auth.bearer}`;
    } else if (mode === "apiKey") {
      if (!this.auth.apiKey) {
        throw new ApiError(0, "no_api_key", "this call requires a partner API key (auth.apiKey)");
      }
      headers["X-API-Key"] = this.auth.apiKey;
    }

    const init: RequestInit = { method, headers };
    if (opts.body !== undefined) init.body = JSON.stringify(opts.body);
    const res = await this.fetchImpl(url, init);

    const text = await res.text();
    let json: unknown;
    try {
      json = text ? JSON.parse(text) : undefined;
    } catch {
      json = undefined;
    }

    if (!res.ok) {
      const j = json as { code?: string; error?: string; message?: string } | undefined;
      throw new ApiError(
        res.status,
        j?.code ?? j?.error,
        j?.message ?? j?.error ?? `HTTP ${res.status} on ${method} ${url}`,
        json,
      );
    }
    return json as T;
  }
}
