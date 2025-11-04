import { NextResponse } from "next/server"
import { ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME } from "@/lib/auth.server"

export async function POST() {
  const response = NextResponse.json({ ok: true })
  response.cookies.delete(ACCESS_COOKIE_NAME)
  response.cookies.delete(REFRESH_COOKIE_NAME)
  return response
}
