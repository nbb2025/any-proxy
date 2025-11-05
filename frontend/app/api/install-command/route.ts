import { NextResponse } from "next/server"
import { cookies } from "next/headers"
import { execFile } from "node:child_process"
import { promisify } from "node:util"
import path from "node:path"
import { existsSync } from "node:fs"
import { ACCESS_COOKIE_NAME } from "@/lib/auth.server"

const execFileAsync = promisify(execFile)

type GenerateRequest = {
  nodeType?: string
  nodeId?: string
  ttlMinutes?: number
  version?: string
  controlPlaneUrl?: string
  reloadCmd?: string
  outputPath?: string
  agentToken?: string
}

function parseEnvOutput(raw: string): Record<string, string> {
  const result: Record<string, string> = {}
  raw
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .forEach((line) => {
      const idx = line.indexOf("=")
      if (idx <= 0) {
        return
      }
      const key = line.slice(0, idx)
      const value = line.slice(idx + 1)
      result[key] = value
    })
  return result
}

export async function POST(request: Request) {
  let payload: GenerateRequest

  try {
    payload = (await request.json()) ?? {}
  } catch {
    return NextResponse.json({ error: "invalid JSON payload" }, { status: 400 })
  }

  const nodeType = (payload.nodeType ?? "edge").toLowerCase()
  const nodeId = payload.nodeId?.trim()
  const version = payload.version?.trim()
  const reloadCmd = payload.reloadCmd?.trim()
  const outputPath = payload.outputPath?.trim()
  const agentToken = payload.agentToken?.trim()
  const ttlCandidate = Number.parseInt(String(payload.ttlMinutes ?? 30), 10)
  const ttlMinutes = Number.isFinite(ttlCandidate) ? Math.max(5, Math.min(ttlCandidate, 720)) : 30

  if (!nodeId) {
    return NextResponse.json({ error: "nodeId is required" }, { status: 400 })
  }
  if (nodeType !== "edge" && nodeType !== "tunnel") {
    return NextResponse.json({ error: "nodeType must be edge or tunnel" }, { status: 400 })
  }

  const repoRoot = path.resolve(process.cwd(), "..")
  const scriptPath = path.resolve(repoRoot, "scripts", "generate-node-command.sh")

  if (!existsSync(scriptPath)) {
    return NextResponse.json({ error: "generate-node-command.sh not found" }, { status: 500 })
  }

  const accessToken = cookies().get?.(ACCESS_COOKIE_NAME)?.value
  if (!accessToken) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 })
  }

  const controlPlaneUrl =
    payload.controlPlaneUrl?.trim() ??
    process.env.INSTALL_CONTROL_PLANE_URL ??
    process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ??
    process.env.CONTROL_PLANE_URL ??
    ""

  const args = ["--type", nodeType, "--node", nodeId, "--format", "env", "--ttl-min", String(ttlMinutes)]
  if (version) {
    args.push("--version", version)
  }
  if (reloadCmd) {
    args.push("--reload", reloadCmd)
  }
  if (outputPath) {
    args.push("--output", outputPath)
  }
  if (controlPlaneUrl) {
    args.push("--control-plane", controlPlaneUrl)
  }
  if (agentToken) {
    args.push("--agent-token", agentToken)
  }

  const execEnv = {
    ...process.env,
    ANYPROXY_OUTPUT_FMT: "env",
  } as NodeJS.ProcessEnv

  if (process.env.INSTALL_TOKENS_DIR) {
    execEnv.ANYPROXY_TOKENS_DIR = process.env.INSTALL_TOKENS_DIR
  }
  if (process.env.ANYPROXY_VERSION && !version) {
    execEnv.ANYPROXY_VERSION = process.env.ANYPROXY_VERSION
  }
  if (controlPlaneUrl) {
    execEnv.CONTROL_PLANE_URL = controlPlaneUrl
  }
  if (agentToken) {
    execEnv.ANYPROXY_AGENT_TOKEN = agentToken
  }

  try {
    const { stdout } = await execFileAsync(scriptPath, args, {
      cwd: repoRoot,
      env: execEnv,
      maxBuffer: 2 * 1024 * 1024,
    })

    const data = parseEnvOutput(stdout)
    const command = data.COMMAND

    if (!command) {
      return NextResponse.json({ error: "failed to build command" }, { status: 500 })
    }

    const expiresAt = Number.parseInt(data.EXPIRES_AT ?? "", 10)
    const expiresAtIso = data.EXPIRES_AT_ISO ?? null

    return NextResponse.json({
      command,
      token: data.TOKEN,
      tokenPath: data.TOKEN_PATH,
      expiresAt,
      expiresAtIso,
      controlPlaneUrl: data.CONTROL_PLANE_URL ?? controlPlaneUrl,
      nodeType: data.NODE_TYPE ?? nodeType,
      nodeId: data.NODE_ID ?? nodeId,
      version: data.VERSION ?? version ?? null,
      reloadCmd: data.RELOAD_CMD ?? reloadCmd ?? null,
      outputPath: data.OUTPUT_PATH ?? outputPath ?? null,
      agentToken: data.AGENT_TOKEN ?? agentToken ?? null,
      ttlMinutes,
    })
  } catch (error: any) {
    const message =
      error?.stderr?.toString()?.trim() ||
      error?.stdout?.toString()?.trim() ||
      error?.message ||
      "command execution failed"
    console.error("[install-command]", message)
    return NextResponse.json({ error: message }, { status: 500 })
  }
}
