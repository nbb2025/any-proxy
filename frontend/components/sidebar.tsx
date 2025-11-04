"use client"

"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { cn } from "@/lib/utils"
import { LayoutDashboard, Network, Database, Shield, Settings, Globe, LogOut } from "lucide-react"

const navigation = [
  { name: "仪表盘", href: "/", icon: LayoutDashboard },
  { name: "边缘节点", href: "/edge", icon: Network },
  { name: "域名上游", href: "/resources", icon: Database },
  { name: "策略中心", href: "/policy", icon: Shield },
  { name: "系统设置", href: "/settings", icon: Settings },
]

export function Sidebar() {
  const pathname = usePathname()
  const router = useRouter()

  const handleLogout = async () => {
    try {
      await fetch("/api/auth/logout", { method: "POST" })
    } catch (error) {
      console.error("[sidebar] logout failed", error)
    } finally {
      router.replace("/login")
    }
  }

  return (
    <div className="flex h-screen w-16 flex-col items-center gap-4 border-r border-border bg-sidebar py-4">
      <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary">
        <Globe className="h-6 w-6 text-primary-foreground" />
      </div>

      <nav className="flex flex-1 flex-col items-center gap-2">
        {navigation.map((item) => {
          const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href))

          return (
            <Link
              key={item.name}
              href={item.href}
              className={cn(
                "flex h-12 w-12 flex-col items-center justify-center gap-1 rounded-lg text-xs transition-colors",
                isActive
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-sidebar-foreground/60 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground",
              )}
            >
              <item.icon className="h-5 w-5" />
              <span className="text-[10px]">{item.name}</span>
            </Link>
          )
        })}
      </nav>

      <button
        onClick={handleLogout}
        className="flex h-10 w-10 items-center justify-center rounded-full bg-muted text-muted-foreground transition hover:bg-red-500/20 hover:text-red-200"
        title="退出登录"
      >
        <LogOut className="h-4 w-4" />
      </button>
    </div>
  )
}
