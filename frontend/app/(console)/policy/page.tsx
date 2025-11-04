import { redirect } from "next/navigation"
import { fetchSnapshot } from "@/lib/api"
import { PolicyTabs } from "@/components/policy/policy-tabs"
import { PolicyList } from "@/components/policy/policy-list"
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

  const summary = {
    total: snapshot.tunnels.length,
    tcp: snapshot.tunnels.filter((item) => item.protocol === "tcp").length,
    udp: snapshot.tunnels.filter((item) => item.protocol === "udp").length,
    quic: snapshot.tunnels.filter((item) => item.protocol === "quic").length,
  }

  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div>
          <h1 className="text-2xl font-semibold text-foreground">隧道与穿透策略</h1>
          <p className="text-sm text-muted-foreground">管理 TCP/UDP/QUIC 等四层转发的监听策略。</p>
        </div>
      </header>

      <div className="flex-1 space-y-6 overflow-auto p-8">
        <PolicyTabs summary={summary} />
        <PolicyList tunnels={snapshot.tunnels} />
      </div>
    </div>
  )
}
