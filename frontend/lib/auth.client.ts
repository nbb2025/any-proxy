'use client'

const STORAGE_KEY = 'anyproxy.auth'
const REFRESH_SKEW_SECONDS = 60

export type StoredAuthTokens = {
  accessToken: string
  refreshToken: string
  expiresAt?: string | null
}

function isBrowser(): boolean {
  return typeof window !== 'undefined' && typeof window.localStorage !== 'undefined'
}

function parseStoredTokens(raw: string | null): StoredAuthTokens | null {
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw)
    if (
      typeof parsed?.accessToken === 'string' &&
      typeof parsed?.refreshToken === 'string'
    ) {
      return {
        accessToken: parsed.accessToken,
        refreshToken: parsed.refreshToken,
        expiresAt: typeof parsed.expiresAt === 'string' ? parsed.expiresAt : null,
      }
    }
  } catch {
    // ignore malformed storage
  }
  return null
}

export function saveAuthTokens(tokens: StoredAuthTokens) {
  if (!isBrowser()) return
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(tokens))
}

export function getStoredTokens(): StoredAuthTokens | null {
  if (!isBrowser()) return null
  const raw = window.localStorage.getItem(STORAGE_KEY)
  return parseStoredTokens(raw)
}

export function clearAuthTokens() {
  if (!isBrowser()) return
  window.localStorage.removeItem(STORAGE_KEY)
}

function secondsUntilExpiry(expiresAt?: string | null): number | undefined {
  if (!expiresAt) return undefined
  const ts = Date.parse(expiresAt)
  if (Number.isNaN(ts)) {
    return undefined
  }
  return Math.floor((ts - Date.now()) / 1000)
}

export async function ensureAccessToken(): Promise<string | undefined> {
  const tokens = getStoredTokens()
  if (!tokens) {
    return undefined
  }
  const remaining = secondsUntilExpiry(tokens.expiresAt)
  if (remaining === undefined || remaining > REFRESH_SKEW_SECONDS) {
    return tokens.accessToken
  }
  const refreshed = await refreshTokens(tokens.refreshToken)
  return refreshed?.accessToken
}

export async function refreshTokens(
  refreshToken: string | undefined,
): Promise<StoredAuthTokens | undefined> {
  if (!refreshToken) {
    clearAuthTokens()
    return undefined
  }
  try {
    const res = await fetch('/api/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
      credentials: 'include',
    })
    if (!res.ok) {
      clearAuthTokens()
      return undefined
    }
    const data = await res.json()
    if (typeof data?.accessToken !== 'string' || typeof data?.refreshToken !== 'string') {
      clearAuthTokens()
      return undefined
    }
    const stored: StoredAuthTokens = {
      accessToken: data.accessToken,
      refreshToken: data.refreshToken,
      expiresAt: typeof data.expiresAt === 'string' ? data.expiresAt : null,
    }
    saveAuthTokens(stored)
    return stored
  } catch {
    clearAuthTokens()
    return undefined
  }
}

export function buildAuthHeaders(
  tokens?: StoredAuthTokens | null,
): Record<string, string> {
  const activeTokens = tokens ?? getStoredTokens()
  if (!activeTokens?.accessToken) {
    return {}
  }
  return {
    Authorization: `Bearer ${activeTokens.accessToken}`,
  }
}
