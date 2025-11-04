import { redirect } from "next/navigation"
import { fetchSnapshot } from "@/lib/api"
import { PolicySummary } from "@/components/policy/policy-summary"
import { SSLPolicyList } from "@/components/policy/ssl-policy-list"
import { AccessPolicyList } from "@/components/policy/access-policy-list"
import { RewriteRuleList } from "@/components/policy/rewrite-rule-list"
import { requireAccessToken } from "@/lib/auth.server"

export default async function PolicyPage() {
  const token = requireAccessToken()
  let snapshot
  try {
    snapshot = await fetchSnapshot(token)
  } catch (error) {
    console.error("[policy] fetch snapshot failed", error)
    redirect("/login")
  }

  const certificatesById = Object.fromEntries(snapshot.certificates.map((item) => [item.id, item]))
  const domainNamesById = Object.fromEntries(snapshot.domains.map((item) => [item.id, item.domain]))

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border/80 px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">策略与插件</h1>
          <p className="text-sm text-muted-foreground">
            通过证书管理、SSL/TLS、访问控制与回源改写策略，为 CDN 请求提供安全与灵活性。
          </p>
        </div>
      </header>

      <div className="flex-1 space-y-10 overflow-auto p-8">
        <PolicySummary
          certificates={snapshot.certificates.length}
          sslPolicies={snapshot.sslPolicies.length}
          accessPolicies={snapshot.accessPolicies.length}
          rewriteRules={snapshot.rewriteRules.length}
        />

        <section className="space-y-4">
          <div>
            <h2 className="text-xl font-semibold text-foreground">SSL/TLS 策略</h2>
            <p className="text-sm text-muted-foreground">
              配置证书、TLS 版本、HSTS 等行为，确保客户端访问体验与安全性。
            </p>
          </div>
          <SSLPolicyList
            policies={snapshot.sslPolicies}
            certificatesById={certificatesById}
            domainNamesById={domainNamesById}
          />
        </section>

        <section className="space-y-4">
          <div>
            <h2 className="text-xl font-semibold text-foreground">访问控制</h2>
            <p className="text-sm text-muted-foreground">
              基于请求来源、路径、Header 等条件执行允许或拒绝策略，保护回源服务。
            </p>
          </div>
          <AccessPolicyList policies={snapshot.accessPolicies} domainNamesById={domainNamesById} />
        </section>

        <section className="space-y-4">
          <div>
            <h2 className="text-xl font-semibold text-foreground">回源请求改写</h2>
            <p className="text-sm text-muted-foreground">
              在边缘节点内灵活改写 Host、SNI、URL、Header 或上游协议，满足复杂回源需求。
            </p>
          </div>
          <RewriteRuleList rules={snapshot.rewriteRules} domainNamesById={domainNamesById} />
        </section>
      </div>
    </div>
  )
}
