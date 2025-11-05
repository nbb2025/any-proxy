import { NextResponse } from "next/server"
import { getControlPlaneURL } from "@/lib/control-plane.server"

export async function POST(request: Request) {
  const controlPlaneURL = getControlPlaneURL()
  if (!controlPlaneURL) {
    return NextResponse.json({ error: "control plane URL not configured" }, { status: 500 })
  }

  let payload: { username?: string; password?: string }
  try {
    payload = (await request.json()) ?? {}
  } catch {
    return NextResponse.json({ error: "invalid payload" }, { status: 400 })
  }

  const username = payload.username?.trim()
  const password = payload.password?.trim()
  if (!username || !password) {
    return NextResponse.json({ error: "username and password required" }, { status: 400 })
  }

  const endpoint = `${controlPlaneURL.replace(/\/$/, "")}/auth/login`
  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
    cache: "no-store",
  })

  if (!res.ok) {
    const detail = await res.json().catch(() => ({}))
    return NextResponse.json({ error: detail?.error ?? "invalid credentials" }, { status: res.status })
  }

  const data = await res.json()
  const response = NextResponse.json({
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresAt: data.expiresAt ?? null,
  })

  return response
}
