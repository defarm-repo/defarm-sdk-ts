/**
 * Projeção didática de um item (issues #16/#19): o JSON completo passa de 4KB e ENTERRA a
 * lição — e despeja detalhes que não ensinam (ex.: os workspace ids dos co-destinatários de um
 * envelope, a exposição do engines#527). Mostramos só o que prova o ponto: os campos claros, e
 * o campo selado aparecendo como ENVELOPE (commitment truncado) — ilegível até pra quem lê o
 * item inteiro. Whitelist de propósito: campo novo entra OCULTO por default.
 */
const CLEAR_KEYS = new Set(["dfid", "sisbov", "chip", "breed", "sex", "weight_kg", "category"]);

export function projectItem(item: unknown): Record<string, unknown> {
  const clear: Record<string, unknown> = {};
  const sealedFields: string[] = [];
  (function walk(o: unknown): void {
    if (Array.isArray(o)) for (const v of o) walk(v);
    else if (o && typeof o === "object") {
      for (const [k, v] of Object.entries(o)) {
        if (CLEAR_KEYS.has(k) && (typeof v === "string" || typeof v === "number")) clear[k] ??= v;
        if (k === "field_path" && typeof v === "string" && !sealedFields.includes(v)) {
          sealedFields.push(v);
        }
        if (/commitment/i.test(k) && typeof v === "string") {
          clear[`↳ ${k}`] ??= `${v.slice(0, 16)}… (o valor em si: ilegível)`;
        }
        walk(v);
      }
    }
  })(item);
  return {
    "campos claros": clear,
    "campos SELADOS (envelope; ninguém lê o valor aqui)": sealedFields,
  };
}
