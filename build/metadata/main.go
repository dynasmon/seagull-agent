package main

import (
	"fmt"

	"github.com/dynasmon/seagull-agent/protocol"
)

func main() {
	fmt.Printf(
		"%d %d %d %d %d %d\n",
		protocol.Version,
		protocol.MinSupportedServer,
		protocol.MaxSupportedServer,
		protocol.EventSchemaVersion,
		protocol.MinEventSchema,
		protocol.MaxEventSchema,
	)
}
