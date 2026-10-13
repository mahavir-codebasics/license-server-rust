// Inline brand logo — avoids <img src> basePath issues behind the /admin proxy.
export function Logo({ className = "h-7 w-7" }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 512 512"
      role="img"
      aria-label="license-server key mark"
      className={className}
    >
      <defs>
        <linearGradient id="key" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fdba74" />
          <stop offset="0.5" stopColor="#f97316" />
          <stop offset="1" stopColor="#ea580c" />
        </linearGradient>
      </defs>
      <g transform="rotate(-45 256 256)" fill="none" stroke="url(#key)">
        <circle cx="168" cy="256" r="66" strokeWidth="40" />
        <rect x="240" y="234" width="196" height="44" rx="22" fill="url(#key)" stroke="none" />
        <rect x="368" y="268" width="26" height="56" rx="9" fill="url(#key)" stroke="none" />
        <rect x="410" y="268" width="26" height="46" rx="9" fill="url(#key)" stroke="none" />
      </g>
    </svg>
  );
}
