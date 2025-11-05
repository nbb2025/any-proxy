import "server-only"

const controlPlaneURL = (process.env.CONTROL_PLANE_API_URL ?? "").trim()

export function getControlPlaneURL(): string {
  return controlPlaneURL
}
