import { cva, type VariantProps } from "class-variance-authority";
import * as React from "react";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider transition-colors",
  {
    variants: {
      variant: {
        default: "border-zinc-700 bg-zinc-800/80 text-zinc-300",
        outline: "border-zinc-700 text-zinc-400",
        info: "border-sky-800 bg-sky-950/70 text-sky-300",
        success: "border-emerald-800 bg-emerald-950/70 text-emerald-300",
        warning: "border-amber-800 bg-amber-950/70 text-amber-300",
        danger: "border-red-800 bg-red-950/70 text-red-300",
        critical: "border-red-700 bg-red-900/80 text-red-50",
        // Confidence tiers — deliberately distinct shapes, not just hues
        // (red-green colorblind users still separate them).
        tierDeterministic: "border-emerald-500 bg-emerald-500 text-zinc-950",
        tierMeasured: "border-blue-600 bg-blue-600/20 text-blue-300",
        tierEmpirical: "border-amber-500 bg-amber-500/15 text-amber-300",
        tierAdvisory:
          "border-zinc-600 border-dashed bg-transparent text-zinc-400",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <span className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}

export { Badge, badgeVariants };
