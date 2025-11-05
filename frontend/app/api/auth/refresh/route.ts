import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME } from "@/lib/auth.server"
import { getControlPlaneExternalURL, getControlPlaneInternalURL } from "@/lib/control-plane.server"

export async function POST() {
  const externalURL = getControlPlaneExternalURL()
  const internalURL = getControlPlaneInternalURL()

  if (!externalURL && !internalURL) {
    return NextResponse.json({ error: "control plane URL not configured" }, { status: 500 })
  }

  const refreshToken = cookies().get?.(REFRESH_COOKIE_NAME)?.value
  if (!refreshToken) {
    return NextResponse.json({ error: "refresh token missing" }, { status: 401 })
  }

  const endpoint = `${(internalURL || externalURL).replace(/\/$/, "")}/auth/refresh`
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken }),
    cache: "no-store",
  })

  if (!res.ok) {
    const response = NextResponse.json({ error: "refresh failed" }, { status: 401 })
    response.cookies.delete?.(ACCESS_COOKIE_NAME)
    response.cookies.delete?.(REFRESH_COOKIE_NAME)
    return response
  }

  const data = await res.json()
  const response = NextResponse.json({ ok: true })
  const accessMaxAge = computeTTLSeconds(data?.expiresAt, 24 * 3600)

  response.cookies.set(ACCESS_COOKIE_NAME, data.accessToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: accessMaxAge,
  })
  response.cookies.set(REFRESH_COOKIE_NAME, data.refreshToken, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/",
    maxAge: 14 * 24 * 3600,
  })
  return response
}

function computeTTLSeconds(expiresAt: unknown, fallback: number): number {
  if (typeof expiresAt === "string") {
    const ts = Date.parse(expiresAt)
    if (!Number.isNaN(ts)) {
      const seconds = Math.floor((ts - Date.now()) / 1000)
      if (seconds > 60) {
        return seconds
      }
    }
  }
  return fallback
}
