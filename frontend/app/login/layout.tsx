import type { ReactNode } from "react"
import { cookies } from "next/headers"
import { redirect } from "next/navigation"
import { ACCESS_COOKIE_NAME } from "@/lib/auth.server"

export default function LoginLayout({ children }: { children: ReactNode }) {
  const token = cookies().get?.(ACCESS_COOKIE_NAME)?.value
  if (token) {
    redirect("/")
  }
  return <>{children}</>
}
