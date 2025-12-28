package capture

import "gitlab.com/nathanmblima/dynasmon-netwatch/agent/internal/capture/utils"

func collectLocalIPs() (map[string]bool, error) {
	return utils.CollectLocalIPs()
}
