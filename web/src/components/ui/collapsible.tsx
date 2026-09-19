import { ChevronRight } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";

interface CollapsibleProps extends React.HTMLAttributes<HTMLDivElement> {
  open: boolean;
  onOpenChange?: (open: boolean) => void;
}

/** Minimal controlled collapsible (shadcn-style surface, zero deps). */
function Collapsible({
  open,
  onOpenChange: _onOpenChange,
  className,
  children,
  ...props
}: CollapsibleProps) {
  return (
    <div
      data-state={open ? "open" : "closed"}
      className={cn("group/collapsible", className)}
      {...props}
    >
      {children}
    </div>
  );
}

interface CollapsibleTriggerProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  chevronClassName?: string;
}

const CollapsibleTrigger = React.forwardRef<
  HTMLButtonElement,
  CollapsibleTriggerProps
>(({ className, children, chevronClassName, onClick, ...props }, ref) => {
  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    onClick?.(e);
  };
  return (
    <button
      ref={ref}
      type="button"
      onClick={handleClick}
      className={cn(
        "flex w-full items-center gap-1.5 text-left focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-600 rounded-sm",
        className,
      )}
      {...props}
    >
      <ChevronRight
        aria-hidden
        className={cn(
          "size-3.5 shrink-0 text-zinc-500 transition-transform duration-200",
          "group-data-[state=open]/collapsible:rotate-90",
          chevronClassName,
        )}
      />
      {children}
    </button>
  );
});
CollapsibleTrigger.displayName = "CollapsibleTrigger";

const CollapsibleContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & { open: boolean }
>(({ className, children, open, ...props }, ref) => {
  return (
    <div
      ref={ref}
      hidden={!open}
      className={cn(
        "overflow-hidden text-sm data-[state=closed]:animate-none",
        className,
      )}
      data-state={open ? "open" : "closed"}
      {...props}
    >
      {children}
    </div>
  );
});
CollapsibleContent.displayName = "CollapsibleContent";

export { Collapsible, CollapsibleTrigger, CollapsibleContent };
