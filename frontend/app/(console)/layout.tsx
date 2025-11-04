import type { ReactNode } from "react"
import { Sidebar } from "@/components/sidebar"
import { requireAccessToken } from "@/lib/auth.server"

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  requireAccessToken()

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}

