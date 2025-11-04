import { ShieldCheck, ShieldQuestion } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Card } from "@/components/ui/card"
import type { Certificate, SSLPolicy } from "@/lib/types"

interface SSLPolicyListProps {
  policies: SSLPolicy[]
  certificatesById: Record<string, Certificate | undefined>
  domainNamesById: Record<string, string | undefined>
}

function describeScope(
  scope: SSLPolicy["scope"],
  domainNamesById: Record<string, string | undefined>,
): { label: string; details?: string } {
  const mode = scope.mode?.toLowerCase() ?? "any"
  if (mode === "any") {
    return { label: "全部域名" }
  }
  if (mode === "resources" && scope.resources.length > 0) {
    const names = scope.resources.map((id) => domainNamesById[id] ?? id)
    return { label: "指定域名", details: names.join("、") }
  }
  if (mode === "tags" && scope.tags.length > 0) {
    return { label: "匹配标签", details: scope.tags.join("、") }
  }
  return { label: "自定义作用域" }
}

export function SSLPolicyList({ policies, certificatesById, domainNamesById }: SSLPolicyListProps) {
  if (policies.length === 0) {
    return (
      <Card className="border-dashed border-border/60 bg-muted/30 p-6 text-sm text-muted-foreground">
        尚未配置 SSL/TLS 策略。
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {policies.map((policy) => {
        const scope = describeScope(policy.scope, domainNamesById)
        const certificate = policy.certificateId ? certificatesById[policy.certificateId] : undefined
        return (
          <Card key={policy.id} className="border-border bg-card p-6 shadow-sm">
            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-primary" />
                  <h3 className="text-lg font-semibold text-foreground">{policy.name}</h3>
                  {policy.description ? (
                    <Badge variant="outline" className="border-slate-400/40 text-xs text-muted-foreground">
                      {policy.description}
                    </Badge>
                  ) : null}
                </div>
                <p className="text-sm text-muted-foreground">{scope.label}</p>
                {scope.details ? <p className="text-sm text-muted-foreground/80">{scope.details}</p> : null}
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {policy.enforceHttps ? <Badge variant="secondary">强制 HTTPS</Badge> : null}
                {policy.enableHsts ? <Badge variant="secondary">HSTS</Badge> : null}
                {policy.enableOcspStapling ? <Badge variant="secondary">OCSP Stapling</Badge> : null}
                {policy.clientAuth ? <Badge variant="secondary">客户端认证</Badge> : null}
              </div>
            </div>

            <div className="mt-4 grid gap-3 text-sm text-muted-foreground md:grid-cols-2">
              <div>
                <p className="font-medium text-foreground/80">证书</p>
                {certificate ? (
                  <p>
                    {certificate.name}
                    {certificate.notAfter ? ` · 到期 ${new Date(certificate.notAfter).toLocaleDateString()}` : ""}
                  </p>
                ) : policy.certificateId ? (
                  <p className="flex items-center gap-1 text-destructive">
                    <ShieldQuestion className="h-4 w-4" />
                    未找到证书 {policy.certificateId}
                  </p>
                ) : (
                  <p>未绑定证书（可用于纯转发）</p>
                )}
                {policy.minTlsVersion ? <p>最小 TLS 版本 {policy.minTlsVersion.toUpperCase()}</p> : null}
              </div>
              <div>
                <p className="font-medium text-foreground/80">额外信息</p>
                {policy.clientCaIds.length > 0 ? (
                  <p>客户端信任 CA: {policy.clientCaIds.map((id) => certificatesById[id]?.name ?? id).join("、")}</p>
                ) : (
                  <p>未配置客户端 CA</p>
                )}
                {policy.hstsMaxAge ? <p>HSTS max-age: {policy.hstsMaxAge}</p> : null}
              </div>
            </div>
          </Card>
        )
      })}
    </div>
  )
}
