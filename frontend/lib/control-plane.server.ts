import "server-only"

const external =
  process.env.CONTROL_PLANE_URL ?? process.env.NEXT_PUBLIC_CONTROL_PLANE_URL ?? ""

const internal =
  process.env.CONTROL_PLANE_INTERNAL_URL && process.env.CONTROL_PLANE_INTERNAL_URL.trim().length > 0
    ? process.env.CONTROL_PLANE_INTERNAL_URL
    : external

export function getControlPlaneExternalURL(): string {
  return external
}

export function getControlPlaneInternalURL(): string {
  return internal
}
