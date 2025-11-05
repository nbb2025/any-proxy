import { NextResponse } from "next/server"
import { getControlPlaneURL } from "@/lib/control-plane.server"

export async function POST(request: Request) {
  const controlPlaneURL = getControlPlaneURL()
  if (!controlPlaneURL) {
    return NextResponse.json({ error: "control plane URL not configured" }, { status: 500 })
  }

  let payload: unknown
  try {
    payload = await request.json()
  } catch {
    return NextResponse.json({ error: "invalid payload" }, { status: 400 })
  }

  const refreshToken = typeof (payload as any)?.refreshToken === "string" ? (payload as any).refreshToken.trim() : ""
  if (!refreshToken) {
    return NextResponse.json({ error: "refresh token required" }, { status: 400 })
  }

  const endpoint = `${controlPlaneURL.replace(/\/$/, "")}/auth/refresh`
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refreshToken }),
    cache: "no-store",
  })

  if (!res.ok) {
    return NextResponse.json({ error: "refresh failed" }, { status: res.status })
  }

  const data = await res.json()
  return NextResponse.json({
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt ?? null,
  })
}
