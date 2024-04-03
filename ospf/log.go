package ospf

import "fmt"

func logDebug(format string, args ...interface{}) {
	fmt.Printf("[DBG] "+format+"\n", args...)
}

func logWarn(format string, args ...interface{}) {
	fmt.Printf("[WRN] "+format+"\n", args...)
}

func logErr(format string, args ...interface{}) {
	fmt.Printf("[ERR] "+format+"\n", args...)
}
