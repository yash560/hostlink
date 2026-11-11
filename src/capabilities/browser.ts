import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Browser, BrowserContext, Page } from "playwright-core";
import { HostlinkError } from "../protocol.js";
import type { Capability } from "../agent/index.js";
import { num, obj, optNum, optStr, str } from "./params.js";

export interface BrowserOptions {
  /**
   * Attach to a browser you already started with --remote-debugging-port,
   * e.g. "http://127.0.0.1:9222". Your open tabs and logins become visible.
   */
  cdpUrl?: string;
  /** Launch mode: run without a window. Default false (you usually want to log in yourself). */
  headless?: boolean;
  /** Launch mode: "chrome", "msedge", "chromium"... Default: try chrome, then msedge, then bundled chromium. */
  channel?: string;
  executablePath?: string;
  /**
   * Launch mode: keep the profile here between runs. Default: a fresh temporary profile
   * that is deleted when the agent stops (nothing stays on the machine).
   */
  userDataDir?: string;
  /** Allow file:// and other non-web URLs. Default false. */
  allowNonWebUrls?: boolean;
  maxTextChars?: number;
  actionTimeoutMs?: number;
}

interface Tab { tabId: string; url: string; title: string; active: boolean }

const WEB_URL = /^(https?:\/\/|about:blank$)/i;

/** Drives one browser on the device with Playwright (playwright-core must be installed). */
export function browserCapability(opts: BrowserOptions = {}): Capability {
  const maxText = opts.maxTextChars ?? 100_000;
  const actionTimeout = opts.actionTimeoutMs ?? 30_000;
  let browser: Browser | null = null;
  let context: BrowserContext | null = null;
  let tempDir: string | null = null;
  let starting: Promise<BrowserContext> | null = null;
  const ids = new WeakMap<Page, string>();
  const pages = new Map<string, Page>();
  let nextId = 1;
  let activeId: string | null = null;
  const startupBlank = new Set<Page>();

  const track = (p: Page): string => {
    let id = ids.get(p);
    if (!id) {
      id = `t${nextId++}`;
      ids.set(p, id);
      pages.set(id, p);
      const tid = id;
      p.on("close", () => { pages.delete(tid); if (activeId === tid) activeId = null; });
    }
    return id;
  };

  const ensure = (): Promise<BrowserContext> => {
    if (context) return Promise.resolve(context);
    if (!starting) {
      starting = launch().then((ctx) => {
        context = ctx;
        for (const p of ctx.pages()) {
          track(p);
          // the empty tab a freshly launched browser starts with gets reused by the first open()
          if (!opts.cdpUrl && p.url() === "about:blank") startupBlank.add(p);
        }
        ctx.on("page", (p) => { activeId = track(p); });
        return ctx;
      }).catch(async (e) => {
        starting = null;
        const dir = tempDir;
        tempDir = null;
        if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
        throw e;
      });
    }
    return starting;
  };

  const launch = async (): Promise<BrowserContext> => {
    const pw = await loadPlaywright();
    if (opts.cdpUrl) {
      browser = await pw.chromium.connectOverCDP(opts.cdpUrl, { timeout: 15_000 });
      const ctx = browser.contexts()[0] ?? (await browser.newContext());
      return ctx;
    }
    const dir = opts.userDataDir ?? (tempDir = await mkdtemp(join(tmpdir(), "hostlink-browser-")));
    const base = { headless: opts.headless ?? false, viewport: null, args: ["--no-first-run", "--no-default-browser-check"] };
    if (opts.executablePath) return pw.chromium.launchPersistentContext(dir, { ...base, executablePath: opts.executablePath });
    const channels = opts.channel ? [opts.channel] : ["chrome", "msedge", undefined];
    let lastErr: unknown;
    for (const channel of channels) {
      try {
        return await pw.chromium.launchPersistentContext(dir, channel ? { ...base, channel } : base);
      } catch (e) { lastErr = e; }
    }
    throw new HostlinkError("browser_unavailable", `No browser could be started. Install Google Chrome, or run "npx playwright-core install chromium". (${(lastErr as Error)?.message?.split("\n")[0] ?? "unknown error"})`);
  };

  const page = async (p: Record<string, unknown>): Promise<Page> => {
    const ctx = await ensure();
    const tabId = optStr(p.tabId, "tabId", 32);
    if (tabId) {
      const pg = pages.get(tabId);
      if (!pg || pg.isClosed()) throw new HostlinkError("tab_not_found", `No open tab ${tabId}`);
      activeId = tabId;
      return pg;
    }
    if (activeId) {
      const pg = pages.get(activeId);
      if (pg && !pg.isClosed()) return pg;
    }
    const open = ctx.pages().filter((x) => !x.isClosed());
    const pg = open[open.length - 1] ?? (await ctx.newPage());
    activeId = track(pg);
    return pg;
  };

  const checkUrl = (url: string) => {
    if (!opts.allowNonWebUrls && !WEB_URL.test(url)) throw new HostlinkError("url_not_allowed", "Only http(s) URLs are allowed");
    return url;
  };

  const tab = async (pg: Page): Promise<Tab> => {
    const tabId = track(pg);
    return { tabId, url: pg.url(), title: await pg.title().catch(() => ""), active: tabId === activeId };
  };

  const waitUntil = (v: unknown) => {
    const w = optStr(v, "waitUntil", 20) ?? "load";
    if (!["load", "domcontentloaded", "networkidle", "commit"].includes(w)) throw new HostlinkError("invalid_params", "waitUntil must be load, domcontentloaded, networkidle or commit");
    return w as "load" | "domcontentloaded" | "networkidle" | "commit";
  };

  const timeout = (p: Record<string, unknown>) => optNum(p.timeoutMs, "timeoutMs", 1, 120_000) ?? actionTimeout;

  return {
    name: "browser",
    methods: {
      tabs: async () => {
        const ctx = await ensure();
        return Promise.all(ctx.pages().filter((x) => !x.isClosed()).map(tab));
      },
      open: async (params) => {
        const p = obj(params ?? {});
        const ctx = await ensure();
        const reuse = [...startupBlank].find((x) => !x.isClosed() && x.url() === "about:blank");
        startupBlank.clear();
        const pg = reuse ?? (await ctx.newPage());
        activeId = track(pg);
        if (p.url !== undefined) await pg.goto(checkUrl(str(p.url, "url", 8192)), { waitUntil: waitUntil(p.waitUntil), timeout: timeout(p) });
        return tab(pg);
      },
      goto: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        const res = await pg.goto(checkUrl(str(p.url, "url", 8192)), { waitUntil: waitUntil(p.waitUntil), timeout: timeout(p) });
        return { ...(await tab(pg)), status: res?.status() ?? null };
      },
      back: async (params) => { const pg = await page(obj(params ?? {})); await pg.goBack({ timeout: actionTimeout }); return tab(pg); },
      forward: async (params) => { const pg = await page(obj(params ?? {})); await pg.goForward({ timeout: actionTimeout }); return tab(pg); },
      reload: async (params) => { const pg = await page(obj(params ?? {})); await pg.reload({ timeout: actionTimeout }); return tab(pg); },
      focus: async (params) => { const pg = await page(obj(params)); await pg.bringToFront(); return tab(pg); },
      close: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        await pg.close();
        return { closed: true };
      },
      click: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        const button = (optStr(p.button, "button", 10) ?? "left") as "left" | "right" | "middle";
        if (!["left", "right", "middle"].includes(button)) throw new HostlinkError("invalid_params", "button must be left, right or middle");
        const clickCount = optNum(p.clickCount, "clickCount", 1, 3) ?? 1;
        if (p.selector !== undefined) await pg.locator(str(p.selector, "selector", 2000)).first().click({ button, clickCount, timeout: timeout(p) });
        else await pg.mouse.click(num(p.x, "x", 0, 100_000), num(p.y, "y", 0, 100_000), { button, clickCount });
        return tab(pg);
      },
      fill: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        await pg.locator(str(p.selector, "selector", 2000)).first().fill(str(p.value, "value", 100_000), { timeout: timeout(p) });
        return { ok: true };
      },
      type: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        await pg.keyboard.type(str(p.text, "text", 100_000), { delay: optNum(p.delayMs, "delayMs", 0, 1000) ?? 0 });
        return { ok: true };
      },
      press: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        await pg.keyboard.press(str(p.key, "key", 64));
        return { ok: true };
      },
      select: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        const values = Array.isArray(p.values) && p.values.every((v) => typeof v === "string") ? (p.values as string[]) : [str(p.value, "value", 2000)];
        return { selected: await pg.locator(str(p.selector, "selector", 2000)).first().selectOption(values, { timeout: timeout(p) }) };
      },
      scroll: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        await pg.mouse.wheel(optNum(p.dx, "dx", -100_000, 100_000) ?? 0, optNum(p.dy, "dy", -100_000, 100_000) ?? 600);
        return { ok: true };
      },
      waitFor: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        const state = (optStr(p.state, "state", 10) ?? "visible") as "visible" | "attached" | "detached" | "hidden";
        if (!["visible", "attached", "detached", "hidden"].includes(state)) throw new HostlinkError("invalid_params", "bad state");
        await pg.locator(str(p.selector, "selector", 2000)).first().waitFor({ state, timeout: timeout(p) });
        return { ok: true };
      },
      text: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        const sel = optStr(p.selector, "selector", 2000) ?? "body";
        const t = await pg.locator(sel).first().innerText({ timeout: timeout(p) });
        return { text: t.slice(0, maxText), truncated: t.length > maxText, url: pg.url() };
      },
      html: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        const sel = optStr(p.selector, "selector", 2000);
        const h = sel ? await pg.locator(sel).first().evaluate((el) => el.outerHTML, undefined, { timeout: timeout(p) }) : await pg.content();
        return { html: h.slice(0, maxText), truncated: h.length > maxText };
      },
      /** Accessibility tree as YAML: the cheapest way for a model to "see" the page. */
      snapshot: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        const s = await pg.locator(optStr(p.selector, "selector", 2000) ?? "body").first().ariaSnapshot({ timeout: timeout(p) });
        return { snapshot: s.slice(0, maxText), truncated: s.length > maxText, url: pg.url(), title: await pg.title() };
      },
      screenshot: async (params) => {
        const p = obj(params ?? {});
        const pg = await page(p);
        const sel = optStr(p.selector, "selector", 2000);
        const buf = sel
          ? await pg.locator(sel).first().screenshot({ type: "png", timeout: timeout(p) })
          : await pg.screenshot({ type: "png", fullPage: p.fullPage === true, timeout: timeout(p) });
        return { mimeType: "image/png", data: buf.toString("base64") };
      },
      /** Runs a JavaScript expression in the page and returns its JSON value. */
      evaluate: async (params) => {
        const p = obj(params);
        const pg = await page(p);
        return { value: await pg.evaluate(str(p.expression, "expression", 100_000)) };
      },
    },
    async dispose() {
      const ctx = context, b = browser, dir = tempDir;
      context = null; browser = null; tempDir = null; starting = null;
      startupBlank.clear(); pages.clear(); activeId = null;
      try {
        if (b) await b.close();
        else if (ctx) await ctx.close();
      } catch { /* already closed */ }
      if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
    },
  };
}

async function loadPlaywright(): Promise<typeof import("playwright-core")> {
  for (const name of ["playwright-core", "playwright"]) {
    try {
      const m = (await import(name)) as typeof import("playwright-core") & { default?: typeof import("playwright-core") };
      return m.chromium ? m : m.default!;
    } catch { /* try next */ }
  }
  throw new HostlinkError("browser_unavailable", 'The browser capability needs "playwright-core" (npm i playwright-core)');
}
