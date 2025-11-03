import { SettingsTabs } from "@/components/settings/settings-tabs"
import { GeneralSettings } from "@/components/settings/general-settings"
import { SecuritySettings } from "@/components/settings/security-settings"
import { NotificationSettings } from "@/components/settings/notification-settings"
import { ApiSettings } from "@/components/settings/api-settings"

export default function SettingsPage() {
  return (
    <div className="flex h-full flex-col">
      <header className="flex items-center justify-between border-b border-border px-8 py-4">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-semibold text-foreground">系统设置</h1>
        </div>
      </header>

      <div className="flex-1 overflow-auto p-8">
        <div className="mx-auto max-w-4xl space-y-6">
          <SettingsTabs />
          <GeneralSettings />
          <SecuritySettings />
          <NotificationSettings />
          <ApiSettings />
        </div>
      </div>
    </div>
  )
}

