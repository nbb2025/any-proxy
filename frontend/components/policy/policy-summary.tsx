import { FileKey2, Lock, Repeat, ShieldCheck } from "lucide-react"
import { Card } from "@/components/ui/card"

interface PolicySummaryProps {
  certificates: number
  sslPolicies: number
  accessPolicies: number
  rewriteRules: number
}

export function PolicySummary({ certificates, sslPolicies, accessPolicies, rewriteRules }: PolicySummaryProps) {
  const items = [
    { key: "certificates", label: "证书管理", value: certificates, icon: FileKey2 },
    { key: "ssl", label: "SSL/TLS 策略", value: sslPolicies, icon: ShieldCheck },
    { key: "access", label: "访问控制", value: accessPolicies, icon: Lock },
    { key: "rewrite", label: "回源改写", value: rewriteRules, icon: Repeat },
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {items.map((item) => {
        const Icon = item.icon
        return (
          <Card
            key={item.key}
            className="flex items-center justify-between border-border/70 bg-card px-5 py-4 shadow-sm"
          >
            <div>
              <p className="text-sm font-medium text-muted-foreground">{item.label}</p>
              <p className="mt-1 text-2xl font-semibold text-foreground">{item.value}</p>
            </div>
            <div className="rounded-full bg-primary/10 p-3">
              <Icon className="h-5 w-5 text-primary" />
            </div>
          </Card>
        )
      })}
    </div>
  )
}
