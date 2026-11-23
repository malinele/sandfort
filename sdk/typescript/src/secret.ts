/** A secret shown once by the server stays readable but out of JSON, `Object.keys` and logs. */

export function withHiddenSecret<T extends object, K extends string>(
  value: T,
  name: K,
  secret: string | undefined,
): T & { readonly [P in K]?: string } {
  if (secret !== undefined) {
    Object.defineProperty(value, name, { value: secret, enumerable: false, writable: false });
  }
  return value as T & { readonly [P in K]?: string };
}
