"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { Loader2, Lock, Globe2 } from "lucide-react"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

export default function LoginPage() {
  const router = useRouter()
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
        credentials: "include",
      })
      if (!res.ok) {
        const detail = await res.json().catch(() => ({}))
        throw new Error(detail?.error ?? "登录失败")
      }
      router.replace("/")
      router.refresh()
      if (typeof window !== "undefined") {
        window.setTimeout(() => {
          window.location.replace("/")
        }, 100)
      } else {
        setLoading(false)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败")
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-screen bg-[#07090F] text-white">
      <div className="hidden flex-1 flex-col justify-between bg-gradient-to-b from-[#0B1030] to-[#051425] p-12 lg:flex">
        <div className="flex items-center gap-3 text-lg font-semibold tracking-wide text-emerald-200">
          <Globe2 className="h-6 w-6" />
          AnyProxy Control Center
        </div>
        <div className="space-y-6">
          <h1 className="text-4xl font-semibold">企业级内网 CDN 控制中心</h1>
          <p className="max-w-md text-base text-slate-300">
            统一管理边缘节点、证书、安全策略与回源配置，让内部服务的分发与治理更安全可靠。
          </p>
          <div className="grid grid-cols-2 gap-6 text-sm text-slate-400">
            <div>
              <p className="text-emerald-300">实时监控</p>
              <p>覆盖请求量、错误率和全局节点健康状态。</p>
            </div>
            <div>
              <p className="text-emerald-300">灵活策略</p>
              <p>支持访问控制、回源改写与证书统一托管。</p>
            </div>
            <div>
              <p className="text-emerald-300">统一配置</p>
              <p>通过控制平面强一致下发，边缘节点自动收敛。</p>
            </div>
            <div>
              <p className="text-emerald-300">全链路安全</p>
              <p>JWT 鉴权、TLS 双向认证、密钥自动轮换。</p>
            </div>
          </div>
        </div>
        <p className="text-sm text-slate-500">© {new Date().getFullYear()} AnyProxy · All Rights Reserved</p>
      </div>

      <div className="flex flex-1 items-center justify-center bg-[#090B15] px-8 py-16">
        <div className="w-full max-w-md space-y-8 rounded-2xl border border-white/5 bg-[#0F1325]/60 p-10 shadow-2xl ring-1 ring-black/20 backdrop-blur">
          <div className="space-y-3 text-center">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-300">
              <Lock className="h-6 w-6" />
            </div>
            <h2 className="text-2xl font-semibold tracking-wide">登录控制台</h2>
            <p className="text-sm text-slate-400">输入凭证以访问 AnyProxy 控制平面</p>
          </div>

          <form className="space-y-6" onSubmit={handleSubmit}>
            <div className="space-y-2">
              <label htmlFor="username" className="text-sm font-medium text-slate-300">
                用户名
              </label>
              <Input
                id="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="输入管理员账号"
                className="border-slate-700 bg-[#0B1020] text-slate-100 placeholder:text-slate-500 focus-visible:border-emerald-400 focus-visible:ring-emerald-400/40"
                autoComplete="username"
                required
              />
            </div>

            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium text-slate-300">
                密码
              </label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="输入控制平面密码"
                className="border-slate-700 bg-[#0B1020] text-slate-100 placeholder:text-slate-500 focus-visible:border-emerald-400 focus-visible:ring-emerald-400/40"
                autoComplete="current-password"
                required
              />
            </div>

            {error && <p className="rounded-md border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-200">{error}</p>}

            <Button
              type="submit"
              className="w-full bg-emerald-500 text-emerald-950 hover:bg-emerald-400"
              disabled={loading}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  正在登录...
                </>
              ) : (
                "登录"
              )}
            </Button>
          </form>

          <p className="text-center text-xs text-slate-500">
            使用过程中有任何问题，请联系平台管理员或参考部署文档。
          </p>
        </div>
      </div>
    </div>
  )
}
