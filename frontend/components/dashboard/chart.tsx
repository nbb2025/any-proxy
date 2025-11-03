export function DashboardChart() {
  return (
    <div className="flex h-48 items-center justify-center rounded-lg border border-border bg-card">
      <div className="relative h-40 w-40">
        <svg className="h-full w-full -rotate-90 transform">
          <circle cx="80" cy="80" r="70" stroke="oklch(0.25 0 0)" strokeWidth="12" fill="none" />
          <circle
            cx="80"
            cy="80"
            r="70"
            stroke="oklch(0.75 0.18 150)"
            strokeWidth="12"
            fill="none"
            strokeDasharray={`${2 * Math.PI * 70 * 0.75} ${2 * Math.PI * 70}`}
            strokeLinecap="round"
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-3xl font-bold text-foreground">671</span>
          <span className="text-sm text-muted-foreground">请求</span>
        </div>
      </div>
    </div>
  )
}
