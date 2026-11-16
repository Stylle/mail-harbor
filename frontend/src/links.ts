// Uses the same plain-text recognition rules as Pocket Relay. Never renders HTML.
export interface TextPart {
  text: string;
  href?: string;
  external?: boolean;
}
const candidates =
  /https?:\/\/[^\s<>"'`，。！？；、【】「」“”‘’]+|www\.[^\s<>"'`，。！？；、【】「」“”‘’]+|(?:mailto:)?[a-z0-9.!#$%&'*+\/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,24}|(?:\+86[ -]?)?1[3-9]\d{9}|\+\d[\d ()-]{5,23}\d/gi;
function trimURL(v: string) {
  v = v.replace(/[.,;!?:]+$/g, "");
  for (const [close, open] of [
    [")", "("],
    ["]", "["],
    ["}", "{"],
  ])
    while (v.endsWith(close) && v.split(close).length > v.split(open).length)
      v = v.slice(0, -1);
  return v;
}
export function parseLinks(text: string): TextPart[] {
  const out: TextPart[] = [];
  let offset = 0,
    count = 0;
  for (const match of text.matchAll(new RegExp(candidates.source, "gi"))) {
    const start = match.index!,
      raw = match[0];
    if (start > 0 && /[a-z0-9_@/:\\.+-]/i.test(text[start - 1])) continue;
    let value = raw,
      href = "",
      external = false;
    if (/^(https?:\/\/|www\.)/i.test(value)) {
      value = trimURL(value);
      try {
        const url = new URL(/^www\./i.test(value) ? "https://" + value : value);
        if (
          ["https:", "http:"].includes(url.protocol) &&
          url.hostname &&
          !url.username &&
          !url.password
        ) {
          href = url.href;
          external = true;
        }
      } catch {}
    } else if (value.includes("@")) {
      const address = value.replace(/^mailto:/i, "");
      const at = address.lastIndexOf("@"),
        local = address.slice(0, at),
        domain = address.slice(at + 1);
      if (
        !local.startsWith(".") &&
        !local.endsWith(".") &&
        !local.includes("..") &&
        domain
          .split(".")
          .every((v) => /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(v))
      )
        href = "mailto:" + encodeURIComponent(local) + "@" + domain;
    } else {
      const digits = value.replace(/[^\d+]/g, "");
      if (
        /^\+?\d{7,15}$/.test(digits) &&
        !/\d/.test(text[start + raw.length] || "")
      )
        href = "tel:" + digits;
    }
    if (!href) continue;
    if (count++ >= 128) break;
    if (start > offset) out.push({ text: text.slice(offset, start) });
    out.push({ text: value, href, external });
    offset = start + value.length;
  }
  if (offset < text.length) out.push({ text: text.slice(offset) });
  return out;
}
