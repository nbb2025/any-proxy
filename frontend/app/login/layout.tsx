'use client'

import type { ReactNode } from "react"
import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { getStoredTokens } from "@/lib/auth.client"

export default function LoginLayout({ children }: { children: ReactNode }) {
  const router = useRouter()

  useEffect(() => {
    const tokens = getStoredTokens()
    if (tokens?.accessToken) {
      router.replace("/")
    }
  }, [router])

  return <>{children}</>
}
