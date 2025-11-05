import "server-only"

import { cookies } from "next/headers"
import { redirect } from "next/navigation"

const ACCESS_COOKIE = "anyproxy_access_token"
const REFRESH_COOKIE = "anyproxy_refresh_token"

export function requireAccessToken(): string {
  const store = cookies()
  const token = store.get?.(ACCESS_COOKIE)?.value
  if (!token) {
    redirect("/login")
  }
  return token
}

export function getAccessToken(): string | undefined {
  return cookies().get?.(ACCESS_COOKIE)?.value
}

export function getRefreshToken(): string | undefined {
  return cookies().get?.(REFRESH_COOKIE)?.value
}

export function clearAuthCookies() {
  const cookieStore = cookies()
  cookieStore.delete?.(ACCESS_COOKIE)
  cookieStore.delete?.(REFRESH_COOKIE)
}

export const ACCESS_COOKIE_NAME = ACCESS_COOKIE
export const REFRESH_COOKIE_NAME = REFRESH_COOKIE
