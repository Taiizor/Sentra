/**
 * Where the bridge looks for tools, and what to change when a tool is outside its PATH, per bridge
 * host OS. Free of imports so the bridge unit tests can check the wording.
 */

/** Where the persisted PATH is read from on the bridge host's OS. */
export function persistedPathLabel(platform: string): string {
  if (platform === 'win32') return 'the persisted system and user PATH (registry)'
  if (platform === 'darwin') return 'the persisted PATH (/etc/paths and /etc/paths.d)'
  if (platform === 'linux') return 'the persisted PATH (/etc/environment)'
  return 'the persisted PATH'
}

/** Every location kind the tool search covers on a platform (used where the search status is unknown). */
export function toolSearchLocations(platform: string | undefined): string {
  return platform
    ? `the bridge process PATH, ${persistedPathLabel(platform)} and standard install locations`
    : 'the bridge process PATH, the persisted PATH and standard install locations'
}

/** Whether the last tool search read the persisted PATH: fully, only partly (macOS), or not at all. */
export type PersistedPathReadState = 'read' | 'partial' | 'unread'

export function persistedPathReadState(toolSearch: { persistedPathRead: boolean; persistedPathError: string | null }): PersistedPathReadState {
  if (!toolSearch.persistedPathRead) return 'unread'
  return toolSearch.persistedPathError ? 'partial' : 'read'
}

/**
 * How to make a restarted bridge on Windows see a changed PATH. A process copies its environment
 * from the process that starts it: Explorer (and so the Start menu) picks up PATH changes, but an
 * application that was already running, such as VS Code, keeps handing its old PATH to the
 * terminals it opens, and services get theirs from the Service Control Manager, which reads it at
 * boot.
 */
const WINDOWS_RESTART =
  'restart the bridge from a terminal opened from the Start menu or Explorer. A terminal inside an application that was already running, such as VS Code, inherits that application’s old PATH, so restart the application first. A bridge run as a Windows service gets PATH changes only after a reboot, unless its service configuration sets PATH.'

const WINDOWS_ADD_TO_PATH =
  'add it to the user or system Path (Settings › System › About › Advanced system settings › Environment Variables)'

/**
 * Why a tool found outside the bridge process PATH is invisible to the bridge, and what to change,
 * for the OS of the bridge host.
 * - persisted: the persisted PATH lists the directory, but the bridge's environment does not.
 * - well_known: the directory is on no PATH the bridge read (usually added by a shell profile).
 *   When the persisted PATH was not (fully) read, whether it lists the directory is unknown, and the
 *   advice says so instead of stating that no PATH lists it.
 */
export function stalePathAdvice(platform: string, kind: 'persisted' | 'well_known', persisted: PersistedPathReadState = 'read'): string {
  if (kind === 'persisted') {
    if (platform === 'win32') {
      return `The persisted PATH in the registry lists their directory, but the bridge process PATH does not: a process copies PATH when it starts, from the program that starts it, so the bridge (or the terminal or application it was started from) predates the PATH change. To pick it up, ${WINDOWS_RESTART}`
    }
    if (platform === 'darwin') {
      return '/etc/paths or /etc/paths.d lists their directory, but the bridge process PATH does not. macOS applies those files through path_helper in login shells only: processes started by launchd (LaunchAgents and LaunchDaemons, apps opened from the Dock or Finder, and the programs they start) get launchd’s minimal PATH, and a shell opened before the change keeps the old one. Start the bridge from a new login shell, or set PATH under EnvironmentVariables in its launchd plist.'
    }
    if (platform === 'linux') {
      return '/etc/environment lists their directory, but the bridge process PATH does not. It is applied by pam_env when a user logs in; systemd services, cron jobs and containers do not read it, and a session started before the change keeps the old PATH. Set Environment=PATH=… in the bridge’s systemd unit (or the service manager’s environment), or start the bridge from a new login shell.'
    }
    return 'The persisted PATH lists their directory, but the bridge process PATH does not. Restart the bridge from an environment that has the updated PATH.'
  }
  const unknown =
    persisted === 'read'
      ? ''
      : `Whether ${persistedPathLabel(platform)} lists their directory is unknown, because it ${persisted === 'partial' ? 'was only partly read' : 'could not be read'}. `
  if (platform === 'win32') {
    if (unknown) {
      return `${unknown}If an installer added the directory there, the bridge started before that change: ${WINDOWS_RESTART} Otherwise, if other programs need it, ${WINDOWS_ADD_TO_PATH} and restart the bridge the same way.`
    }
    return `Their directory is on neither the process PATH nor the persisted PATH: the installer did not add it. If other programs need it, ${WINDOWS_ADD_TO_PATH}, then ${WINDOWS_RESTART}`
  }
  if (platform === 'darwin') {
    return `${unknown}Directories such as /opt/homebrew/bin, ~/.cargo/bin and ~/.local/bin are usually added to PATH by shell profiles (~/.zprofile, ~/.zshrc, ~/.bash_profile), which processes started by launchd never read. Start the bridge from a login shell that has them, or add the directory to PATH in its launchd plist (or to /etc/paths.d for every login shell).`
  }
  if (platform === 'linux') {
    return `${unknown}Directories such as ~/.cargo/bin, ~/.local/bin and /home/linuxbrew/.linuxbrew/bin are usually added to PATH by shell profiles (~/.profile, ~/.bashrc), which systemd services and cron jobs never read. Start the bridge from a login shell that has them, or set Environment=PATH=… in its systemd unit. /snap/bin is not added by a shell profile: snapd adds it for login shells (/etc/profile.d/apps-bin-path.sh) and, through its systemd environment generator, for systemd services, so it is missing from cron jobs, containers, units that set their own PATH and sessions started before snapd was installed.`
  }
  return `${unknown}Their directory is on no PATH the bridge read. Add it to the PATH of the environment that starts the bridge.`
}
