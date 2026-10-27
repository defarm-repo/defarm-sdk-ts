/**
 * Recipe: split de valor por tempo de custódia (cria → recria → engorda).
 *
 * Um animal costuma passar por mais de uma propriedade antes de o ganho ser
 * realizado. A pergunta de sempre: qual a parte de cada fase? Esta recipe
 * responde com a regra mais simples, proporcional aos dias de custódia.
 *
 * É uma função pura, sem chamada de rede. Em produção as janelas de custódia
 * vêm do histórico do item; aqui usamos um histórico de exemplo para o cálculo
 * rodar sem ambiente nem API key:
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
  value: number; // na mesma unidade de totalValue (ex.: arroba, R$)
}

/**
 * Divide `totalValue` entre as partes proporcionalmente aos dias de custódia.
 * Supõe janelas sem sobreposição. Cada valor é arredondado a 2 casas, então a
 * soma pode diferir de totalValue em centavos.
 */
function calculateCustodySplit(
  windows: CustodyWindow[],
  totalValue: number,
): CustodySplit[] {
  const dayMs = 1000 * 60 * 60 * 24;
  const daysByParty = windows.map((w) => ({
    party: w.party,
    days: Math.max(0, (w.leftAt.getTime() - w.enteredAt.getTime()) / dayMs),
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

const totalArrobas = 21.4; // ganho de peso do ciclo inteiro, em @

const split = calculateCustodySplit(exampleHistory, totalArrobas);

console.table(split);
/*
┌─────────┬───────────────────┬──────────┬────────┬───────┐
│ (index) │ party             │ daysHeld │ share  │ value │
├─────────┼───────────────────┼──────────┼────────┼───────┤
│ 0       │ 'fazenda-cria'    │ 161      │ 0.388  │ 8.3   │
│ 1       │ 'fazenda-recria'  │ 138      │ 0.3325 │ 7.12  │
│ 2       │ 'fazenda-engorda' │ 116      │ 0.2795 │ 5.98  │
└─────────┴───────────────────┴──────────┴────────┴───────┘
*/

export { calculateCustodySplit };
export type { CustodyWindow, CustodySplit };
