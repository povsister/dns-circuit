package ospf

import "fmt"

func logDebug(format string, args ...interface{}) {
	fmt.Printf("[DBG] "+format+"\n\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf("[WRN] "+format+"\n\n", args...)
}

func logErr(format string, args ...interface{}) {
	fmt.Printf("[ERR] "+format+"\n\n", args...)
}
