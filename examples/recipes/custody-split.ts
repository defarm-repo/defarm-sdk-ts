/**
 * Recipe: split de valor por tempo de custódia (cria → recria → engorda).
 *
 * Um animal costuma passar por mais de uma propriedade antes da venda. Quando
 * as partes combinam dividir o valor final pelo tempo que cada uma ficou com
 * o animal, a conta é esta: parte proporcional aos dias de custódia. É uma
 * convenção entre as partes, não uma medida do que cada fase produziu (isso
 * se mede por pesagem).
 *
 * É uma função pura, sem chamada de rede. As janelas de custódia são entrada
 * sua (por exemplo, montadas a partir das datas de entrada e saída que você
 * registra); aqui usamos um histórico de exemplo para o cálculo rodar sem
 * ambiente nem API key:
 *
 *   npx tsx examples/recipes/custody-split.ts
 */

interface CustodyWindow {
  party: string;
  enteredAt: Date;
  leftAt: Date;
}

interface CustodySplit {
  party: string;
  daysHeld: number;
  share: number; // 0..1
  value: number; // na mesma unidade de totalValue (ex.: R$)
}

/**
 * Divide `totalValue` entre as partes proporcionalmente aos dias de custódia.
 * Recusa data inválida, saída antes da entrada e janelas sobrepostas. Cada
 * valor é arredondado a 2 casas, então a soma pode diferir de totalValue em
 * centavos.
 */
function calculateCustodySplit(
  windows: CustodyWindow[],
  totalValue: number,
): CustodySplit[] {
  const dayMs = 1000 * 60 * 60 * 24;

  for (const w of windows) {
    if (Number.isNaN(w.enteredAt.getTime()) || Number.isNaN(w.leftAt.getTime())) {
      throw new Error(`invalid date in custody window of ${w.party}`);
    }
    if (w.leftAt.getTime() < w.enteredAt.getTime()) {
      throw new Error(`custody window of ${w.party} ends before it starts`);
    }
  }

  const sorted = [...windows].sort((a, b) => a.enteredAt.getTime() - b.enteredAt.getTime());
  sorted.slice(1).forEach((next, i) => {
    const prev = sorted[i]!;
    if (next.enteredAt.getTime() < prev.leftAt.getTime()) {
      throw new Error(`custody windows of ${prev.party} and ${next.party} overlap`);
    }
  });

  const daysByParty = windows.map((w) => ({
    party: w.party,
    days: (w.leftAt.getTime() - w.enteredAt.getTime()) / dayMs,
  }));

  const totalDays = daysByParty.reduce((sum, p) => sum + p.days, 0);
  if (totalDays === 0) {
    throw new Error("custody windows have zero total days: nothing to split");
  }

  return daysByParty.map(({ party, days }) => {
    const share = days / totalDays;
    return {
      party,
      daysHeld: Math.round(days),
      share: Number(share.toFixed(4)),
      value: Number((share * totalValue).toFixed(2)),
    };
  });
}

// Exemplo com dados ilustrativos (não são dados de produção).

const exampleHistory: CustodyWindow[] = [
  { party: "fazenda-cria", enteredAt: new Date("2026-01-10"), leftAt: new Date("2026-06-20") }, // 161 dias
  { party: "fazenda-recria", enteredAt: new Date("2026-06-20"), leftAt: new Date("2026-11-05") }, // 138 dias
  { party: "fazenda-engorda", enteredAt: new Date("2026-11-05"), leftAt: new Date("2027-03-01") }, // 116 dias
];

const saleValue = 6500; // valor de venda do animal, em R$

const split = calculateCustodySplit(exampleHistory, saleValue);

console.table(split);
/*
┌─────────┬───────────────────┬──────────┬────────┬─────────┐
│ (index) │ party             │ daysHeld │ share  │ value   │
├─────────┼───────────────────┼──────────┼────────┼─────────┤
│ 0       │ 'fazenda-cria'    │ 161      │ 0.388  │ 2521.69 │
│ 1       │ 'fazenda-recria'  │ 138      │ 0.3325 │ 2161.45 │
│ 2       │ 'fazenda-engorda' │ 116      │ 0.2795 │ 1816.87 │
└─────────┴───────────────────┴──────────┴────────┴─────────┘
*/

export { calculateCustodySplit };
export type { CustodyWindow, CustodySplit };
