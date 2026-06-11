import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  configPath,
  loadConfig,
  setConfigValue,
  getConfigValue,
  resetConfig,
  saveLastUrl,
  loadLastUrl,
  CONFIG_KEYS,
} from "../../src/config/store.js";

describe("configPath", () => {
  it("uses XDG_CONFIG_HOME when set", () => {
    const p = configPath({ XDG_CONFIG_HOME: "/xdg" }, "linux", "/home/u");
    expect(p.replaceAll("\\", "/")).toBe("/xdg/deadrop/config.json");
  });

  it("falls back to ~/.config on linux/mac", () => {
    const p = configPath({}, "linux", "/home/u");
    expect(p.replaceAll("\\", "/")).toBe("/home/u/.config/deadrop/config.json");
  });

  it("falls back to ~/.deadrop on Windows", () => {
    const p = configPath({}, "win32", "C:\\Users\\u");
    expect(p.replaceAll("\\", "/")).toBe("C:/Users/u/.deadrop/config.json");
  });

  it("honors XDG_CONFIG_HOME even on Windows", () => {
    const p = configPath({ XDG_CONFIG_HOME: "D:\\cfg" }, "win32", "C:\\Users\\u");
    expect(p.replaceAll("\\", "/")).toBe("D:/cfg/deadrop/config.json");
  });
});

describe("config store CRUD", () => {
  let dir: string;
  let file: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "deadrop-test-"));
    file = join(dir, "deadrop", "config.json");
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("loads empty config when file does not exist", () => {
    expect(loadConfig(file)).toEqual({});
  });

  it("set + get round-trips and persists JSON", () => {
    setConfigValue(file, "server", "https://secrets.example.com");
    expect(getConfigValue(file, "server")).toBe("https://secrets.example.com");
    const onDisk = JSON.parse(readFileSync(file, "utf8"));
    expect(onDisk.server).toBe("https://secrets.example.com");
  });

  it("validates keys", () => {
    expect(() => setConfigValue(file, "bogus", "x")).toThrow(/unknown config key/i);
    expect(() => getConfigValue(file, "bogus")).toThrow(/unknown config key/i);
    expect(CONFIG_KEYS).toEqual(["server", "default-ttl", "output"]);
  });

  it("validates values on set", () => {
    expect(() => setConfigValue(file, "server", "not-a-url")).toThrow(/url/i);
    expect(() => setConfigValue(file, "default-ttl", "8d")).toThrow(/7 days/i);
    expect(() => setConfigValue(file, "output", "yaml")).toThrow(/human|json|quiet/i);
    setConfigValue(file, "default-ttl", "24h");
    setConfigValue(file, "output", "json");
  });

  it("reset removes the config file and last-url state", () => {
    setConfigValue(file, "server", "https://x.example");
    saveLastUrl(file, "https://deadrop.dev/s/x#y");
    resetConfig(file);
    expect(existsSync(file)).toBe(false);
    expect(loadLastUrl(file)).toBeNull();
    expect(loadConfig(file)).toEqual({});
  });

  it("stores and loads last sent URL", () => {
    expect(loadLastUrl(file)).toBeNull();
    saveLastUrl(file, "https://deadrop.dev/s/abc#key");
    expect(loadLastUrl(file)).toBe("https://deadrop.dev/s/abc#key");
  });

  it("tolerates corrupt config file (treats as empty)", () => {
    setConfigValue(file, "server", "https://x.example");
    writeFileSync(file, "{not json");
    expect(loadConfig(file)).toEqual({});
  });
});
