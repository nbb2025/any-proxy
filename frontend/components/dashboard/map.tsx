import { Card } from "@/components/ui/card"

export function DashboardMap() {
  return (
    <Card className="border-border bg-card p-6">
      <div className="relative h-[400px] overflow-hidden rounded-lg bg-muted/20">
        <svg className="h-full w-full" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid meet">
          {/* Simplified world map outline */}
          <path
            d="M 100 150 L 150 140 L 200 160 L 250 150 L 300 170 L 350 160 L 400 180 L 450 170 L 500 190 L 550 180 L 600 200 L 650 190 L 700 210"
            fill="none"
            stroke="oklch(0.35 0 0)"
            strokeWidth="1"
          />

          {/* Location markers */}
          <circle cx="250" cy="180" r="8" fill="oklch(0.65 0.15 200)" opacity="0.8" />
          <circle cx="450" cy="160" r="8" fill="oklch(0.65 0.15 200)" opacity="0.8" />
          <circle cx="600" cy="170" r="8" fill="oklch(0.65 0.15 200)" opacity="0.8" />

          {/* Glow effect */}
          <circle cx="250" cy="180" r="16" fill="oklch(0.65 0.15 200)" opacity="0.2" />
          <circle cx="450" cy="160" r="16" fill="oklch(0.65 0.15 200)" opacity="0.2" />
          <circle cx="600" cy="170" r="16" fill="oklch(0.65 0.15 200)" opacity="0.2" />
        </svg>

        <div className="absolute bottom-4 left-4 flex items-center gap-2 rounded-md bg-background/80 px-3 py-1.5 backdrop-blur-sm">
          <div className="h-2 w-2 rounded-full bg-primary" />
          <span className="text-xs text-foreground">mapbox</span>
        </div>
      </div>
    </Card>
  )
}
