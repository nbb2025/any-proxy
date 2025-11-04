import { Lock, Unlock } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import type { AccessPolicy } from "@/lib/types"

interface AccessPolicyListProps {
  policies: AccessPolicy[]
  domainNamesById: Record<string, string | undefined>
}

function describeScope(policy: AccessPolicy, domainNamesById: Record<string, string | undefined>) {
  const scope = policy.scope
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

function describeCondition(policy: AccessPolicy) {
  if (policy.condition.mode?.toLowerCase() !== "matchers" || policy.condition.matchers.length === 0) {
    return "无额外条件"
  }
  return `${policy.condition.matchers.length} 条匹配条件`
}

export function AccessPolicyList({ policies, domainNamesById }: AccessPolicyListProps) {
  if (policies.length === 0) {
    return (
      <Card className="border-dashed border-border/60 bg-muted/30 p-6 text-sm text-muted-foreground">
        尚未配置访问控制策略。
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {policies.map((policy) => {
        const action = policy.action?.toLowerCase() === "deny" ? "deny" : "allow"
        const Icon = action === "deny" ? Lock : Unlock
        return (
          <Card key={policy.id} className="border-border bg-card p-6 shadow-sm">
            <div className="flex flex-col gap-2 md:flex-row md:items-start md:justify-between">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <Icon className="h-5 w-5 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">{policy.name}</h3>
                  {policy.description ? (
                    <Badge variant="outline" className="border-slate-400/40 text-xs text-muted-foreground">
                      {policy.description}
                    </Badge>
                  ) : null}
                </div>
                <p className="text-sm text-muted-foreground">{describeScope(policy, domainNamesById)}</p>
                <p className="text-sm text-muted-foreground/80">{describeCondition(policy)}</p>
              </div>
              <Badge variant={action === "deny" ? "destructive" : "secondary"} className="self-start">
                {action === "deny" ? "拒绝访问" : "允许访问"}
              </Badge>
            </div>

            <div className="mt-4 grid gap-3 text-sm text-muted-foreground md:grid-cols-2">
              <div>
                <p className="font-medium text-foreground/80">响应处理</p>
                {action === "deny" ? (
                  <p>
                    返回状态码 {policy.responseCode ?? 403}
                    {policy.redirectUrl ? ` · 重定向到 ${policy.redirectUrl}` : ""}
                  </p>
                ) : (
                  <p>允许请求通过</p>
                )}
              </div>
              <div>
                <p className="font-medium text-foreground/80">条件</p>
                {policy.condition.mode?.toLowerCase() === "matchers" && policy.condition.matchers.length > 0 ? (
                  <ul className="space-y-1">
                    {policy.condition.matchers.map((matcher, index) => (
                      <li key={`${policy.id}-matcher-${index}`}>
                        {matcher.type}
                        {matcher.key ? ` · ${matcher.key}` : ""}
                        {matcher.operator ? ` · ${matcher.operator}` : ""}
                        {matcher.values && matcher.values.length > 0 ? ` → ${matcher.values.join(", ")}` : ""}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>无匹配限制</p>
                )}
              </div>
            </div>
          </Card>
        )
      })}
    </div>
  )
}
