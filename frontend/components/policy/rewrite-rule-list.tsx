import { GitCompare, Wrench } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import type { RewriteRule } from "@/lib/types"

interface RewriteRuleListProps {
  rules: RewriteRule[]
  domainNamesById: Record<string, string | undefined>
}

function describeScope(rule: RewriteRule, domainNamesById: Record<string, string | undefined>) {
  const scope = rule.scope
  const mode = scope.mode?.toLowerCase() ?? "any"
  if (mode === "any") {
    return "全部域名"
  }
  if (mode === "resources" && scope.resources.length > 0) {
    const names = scope.resources.map((id) => domainNamesById[id] ?? id)
    return `域名：${names.join("、")}`
  }
  if (mode === "tags" && scope.tags.length > 0) {
    return `标签：${scope.tags.join("、")}`
  }
  return "自定义作用域"
}

function describeActions(rule: RewriteRule): string[] {
  const actions: string[] = []
  if (rule.actions.sniOverride) {
    actions.push(`SNI → ${rule.actions.sniOverride}`)
  }
  if (rule.actions.hostOverride) {
    actions.push(`Host → ${rule.actions.hostOverride}`)
  }
  if (rule.actions.url) {
    const parts: string[] = []
    if (rule.actions.url.mode) parts.push(rule.actions.url.mode)
    if (rule.actions.url.path) parts.push(`路径 ${rule.actions.url.path}`)
    if (rule.actions.url.query) parts.push(`查询 ${rule.actions.url.query}`)
    actions.push(`URL ${parts.join(" / ")}`)
  }
  if (rule.actions.headers && rule.actions.headers.length > 0) {
    actions.push(`请求头 ${rule.actions.headers.length} 项`)
  }
  if (rule.actions.upstream) {
    const { upstream } = rule.actions
    const desc = [
      upstream.scheme ? `协议 ${upstream.scheme}` : null,
      upstream.upstreamHost ? `主机 ${upstream.upstreamHost}` : null,
      upstream.passHostHeader ? "保留 Host" : null,
    ]
    actions.push(`上游设置 ${desc.filter(Boolean).join(" · ")}`)
  }
  return actions.length > 0 ? actions : ["无具体动作"]
}

export function RewriteRuleList({ rules, domainNamesById }: RewriteRuleListProps) {
  if (rules.length === 0) {
    return (
      <Card className="border-dashed border-border/60 bg-muted/30 p-6 text-sm text-muted-foreground">
        尚未配置回源改写规则。
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {rules.map((rule) => (
        <Card key={rule.id} className="border-border bg-card p-6 shadow-sm">
          <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <Wrench className="h-5 w-5 text-primary" />
                <h3 className="text-lg font-semibold text-foreground">{rule.name}</h3>
                {rule.description ? (
                  <Badge variant="outline" className="border-slate-400/40 text-xs text-muted-foreground">
                    {rule.description}
                  </Badge>
                ) : null}
              </div>
              <p className="text-sm text-muted-foreground">{describeScope(rule, domainNamesById)}</p>
              <div className="flex flex-wrap gap-2">
                {describeActions(rule).map((action) => (
                  <Badge key={`${rule.id}-${action}`} variant="secondary" className="bg-primary/10 text-primary">
                    <GitCompare className="mr-1 h-3 w-3" />
                    {action}
                  </Badge>
                ))}
              </div>
            </div>
            <Badge variant="outline" className="self-start border-primary/40 text-primary">
              优先级 {rule.priority}
            </Badge>
          </div>

          {rule.condition.mode?.toLowerCase() === "matchers" && rule.condition.matchers.length > 0 ? (
            <div className="mt-4 text-sm text-muted-foreground">
              <p className="font-medium text-foreground/80">匹配条件</p>
              <ul className="mt-1 space-y-1">
                {rule.condition.matchers.map((matcher, index) => (
                  <li key={`${rule.id}-matcher-${index}`}>
                    {matcher.type}
                    {matcher.key ? ` · ${matcher.key}` : ""}
                    {matcher.operator ? ` · ${matcher.operator}` : ""}
                    {matcher.values && matcher.values.length > 0 ? ` → ${matcher.values.join(", ")}` : ""}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Card>
      ))}
    </div>
  )
}
