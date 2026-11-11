import { HostlinkError, isPlainObject } from "../protocol.js";

export function obj(v: unknown): Record<string, unknown> {
  if (!isPlainObject(v)) throw new HostlinkError("invalid_params", "params must be an object");
  return v;
}
export function str(v: unknown, name: string, max: number): string {
  if (typeof v !== "string" || v.length > max) throw new HostlinkError("invalid_params", `${name} must be a string`);
  return v;
}
export function num(v: unknown, name: string, min: number, max: number): number {
  if (typeof v !== "number" || !Number.isFinite(v) || v < min || v > max) throw new HostlinkError("invalid_params", `${name} must be a number between ${min} and ${max}`);
  return Math.floor(v);
}
export function optStr(v: unknown, name: string, max: number): string | undefined {
  return v === undefined || v === null ? undefined : str(v, name, max);
}
export function optNum(v: unknown, name: string, min: number, max: number): number | undefined {
  return v === undefined || v === null ? undefined : num(v, name, min, max);
}
