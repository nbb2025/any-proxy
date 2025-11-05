'use client'

import { useEffect, useState } from "react"
import type { ReactNode } from "react"
import { useRouter } from "next/navigation"
import { Sidebar } from "@/components/sidebar"
import { ensureAccessToken, clearAuthTokens } from "@/lib/auth.client"

export default function ConsoleLayout({ children }: { children: ReactNode }) {
  const router = useRouter()
  const [ready, setReady] = useState(false)

  useEffect(() => {
    let cancelled = false
    const verify = async () => {
      const token = await ensureAccessToken()
      if (cancelled) {
        return
      }
      if (!token) {
        clearAuthTokens()
        router.replace("/login")
        return
      }
      setReady(true)
    }
    void verify()
    return () => {
      cancelled = true
    }
  }, [router])

  if (!ready) {
    return (
      <div className="flex h-screen items-center justify-center bg-background text-sm text-muted-foreground">
        正在校验登录状态...
      </div>
    )
  }

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-auto">{children}</main>
    </div>
  )
}
