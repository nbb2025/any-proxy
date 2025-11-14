import { NextResponse } from "next/server"
import { getControlPlaneURL } from "@/lib/control-plane.server"

type GenerateRequest = {
  nodeType?: string
  nodeId?: string
  nodeName?: string
  nodeCategory?: string
  groupId?: string
  controlPlaneUrl?: string
  agentToken?: string
}

export async function POST(request: Request) {
  let payload: GenerateRequest

  try {
    payload = (await request.json()) ?? {}
  } catch {
    return NextResponse.json({ error: "invalid JSON payload" }, { status: 400 })
  }

  const requestedType = payload.nodeType ? payload.nodeType.trim().toLowerCase() : undefined
  const nodeType = requestedType === "tunnel" ? "tunnel" : "edge"
  const nodeId = payload.nodeId?.trim()
  const nodeName = payload.nodeName?.trim()
  const nodeCategory = payload.nodeCategory?.trim()
  const groupId = payload.groupId?.trim()

  if (requestedType && requestedType !== "edge" && requestedType !== "tunnel") {
    return NextResponse.json({ error: "nodeType must be edge or tunnel" }, { status: 400 })
  }

  const authHeader = request.headers.get("authorization") ?? ""
  let bearerToken: string | undefined
  if (authHeader.toLowerCase().startsWith("bearer ")) {
    bearerToken = authHeader.slice(7).trim()
  }
  const accessToken = bearerToken
  if (!accessToken) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 })
  }

  const providedAgentToken = payload.agentToken?.trim()
  const agentToken = providedAgentToken && providedAgentToken.length > 0 ? providedAgentToken : accessToken

  let controlPlaneUrl = payload.controlPlaneUrl?.trim() ?? process.env.INSTALL_CONTROL_PLANE_URL ?? ""

  if (!controlPlaneUrl) {
    const host = request.headers.get("host") ?? ""
    const proto = request.headers.get("x-forwarded-proto") ?? "http"
    controlPlaneUrl = host ? `${proto}://${host}` : getControlPlaneURL() ?? ""
  }

  const normalizedBase = controlPlaneUrl.replace(/\/$/, "")
  const installUrl = `${normalizedBase}/install/edge-install.sh`
  const uninstallUrl = `${normalizedBase}/install/edge-uninstall.sh`

  const envVars: string[] = [
    `ANYPROXY_CONTROL_PLANE=${shellEscape(controlPlaneUrl)}`,
    `ANYPROXY_NODE_TYPE=${shellEscape(nodeType)}`,
  ]

  if (nodeId) envVars.push(`ANYPROXY_NODE_ID=${shellEscape(nodeId)}`)
  if (nodeName) envVars.push(`ANYPROXY_NODE_NAME=${shellEscape(nodeName)}`)
  if (groupId) envVars.push(`ANYPROXY_NODE_GROUP_ID=${shellEscape(groupId)}`)
  if (nodeCategory) envVars.push(`ANYPROXY_NODE_CATEGORY=${shellEscape(nodeCategory)}`)
  if (agentToken) envVars.push(`ANYPROXY_AGENT_TOKEN=${shellEscape(agentToken)}`)

  const command = `curl -fsSL ${installUrl} | sudo ${envVars.join(" ")} bash`
  const uninstallEnv: string[] = [
    `ANYPROXY_NODE_TYPE=${shellEscape(nodeType)}`,
    nodeId ? `ANYPROXY_NODE_ID=${shellEscape(nodeId)}` : "ANYPROXY_NODE_ID=<节点ID>",
  ]
  const uninstallCommand = `curl -fsSL ${uninstallUrl} | sudo ${uninstallEnv.join(" ")} bash`

  return NextResponse.json({
    command,
    controlPlaneUrl,
    nodeType,
    nodeId: nodeId || null,
    nodeName: nodeName || null,
    nodeCategory: nodeCategory || null,
    groupId: groupId || null,
    agentToken: agentToken || null,
    uninstallCommand,
    autoGeneratesNodeId: !nodeId,
  })
}

function shellEscape(str: string): string {
  if (!str) return "''"
  if (!/[^a-zA-Z0-9_\-.,:/]/.test(str)) return str
  return `'${str.replace(/'/g, "'\\''")}'`
}
