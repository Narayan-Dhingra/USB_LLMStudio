import React from "react";

// USB-drive + spark brand mark (same artwork as assets/branding/logo/mark.svg).
// The connector tongue and spark stay accent orange; the drive body follows
// currentColor so the mark works in every theme.
export default function BrandMark({ size = 24, className, title = "USB LLM Studio" }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 100 100" role="img" aria-label={title}>
      <path fill="#ff6a3d" d="M8 42a4 4 0 0 1 4-4h26a4 4 0 0 1 4 4v16a4 4 0 0 1-4 4H12a4 4 0 0 1-4-4V42Z" />
      <path fill="#0d0d0f" d="M14 45h4v10h-4zM23 45h4v10h-4z" />
      <path fill="currentColor" d="M38 28h46a10 10 0 0 1 10 10v24a10 10 0 0 1-10 10H38a10 10 0 0 1-10-10V38a10 10 0 0 1 10-10Z" />
      <path fill="#ff6a3d" d="M66 36l5 10 10 4-10 4-5 10-5-10-10-4 10-4Z" />
    </svg>
  );
}
