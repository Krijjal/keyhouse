/**
 * A key lying on its side: the bow (ring) on the left, the blade with its cuts on the right.
 * Each page passes its own `cuts`, so every page gets a different key.
 * Each cut is a depth from 0 (shallow) to 5 (deep), like the bitting code of a real key.
 */
export function Key({ cuts, className }: { cuts: readonly number[]; className: string }) {
  const top = 13;
  const bottom = 31;
  const shoulder = 40;
  const firstCut = shoulder + 26;
  const spacing = 30;

  let blade = `M ${shoulder} ${top}`;
  cuts.forEach((depth, i) => {
    const center = firstCut + i * spacing;
    const y = top + 2.5 + Math.min(Math.max(depth, 0), 5) * 2.4;
    blade += ` L ${center - 10} ${top} L ${center - 3} ${y} L ${center + 3} ${y} L ${center + 10} ${top}`;
  });
  const tipStart = firstCut + (cuts.length - 1) * spacing + 26;
  blade += ` L ${tipStart} ${top} L ${tipStart + 13} ${(top + bottom) / 2} L ${tipStart} ${bottom}`;
  blade += ` L ${shoulder} ${bottom} Z`;

  return (
    <svg
      className={`key ${className}`}
      viewBox={`-1 -1 ${tipStart + 16} 46`}
      aria-hidden="true"
      focusable="false"
    >
      {/* The bow, with its hole, joined to the blade by a short neck. */}
      <circle cx="20" cy="22" r="17" pathLength={1} />
      <circle cx="13" cy="22" r="4.5" pathLength={1} />
      <path d={`M 37 18 L ${shoulder} 18 M 37 26 L ${shoulder} 26`} pathLength={1} />
      <path d={blade} pathLength={1} />
    </svg>
  );
}
